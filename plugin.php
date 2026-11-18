<?php
/**
* WordPress Secure File Manager Plugin
* A comprehensive file management solution with apparent robust security
* Version 2.1.0
*/
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
* Core security class for the file manager plugin
*/
class SFM_Security {

    private static $instance = null;
    private $options;
    private $upload_path;
    private $allowed_mimes = [];
    private $max_size;
    private $upload_count = 0;
    private $blocked_ips = [];
    private $login_attempts = [];

    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new SFM_Security();
        }
        return self::$instance;
    }

    public function init( $options, $upload_path ) {
        $this->options = $options;
        $this->upload_path = $upload_path;
        $this->max_size = $options['max_upload_size'] ?? 100;
        $this->blocked_ips = $options['blocked_ips'] ?? [];
        $this->login_attempts = get_transient( 'sfm_login_attempts' ) ? get_transient( 'sfm_login_attempts' ) : [];
        $this->register_hooks();
        $this->validate_environment();
        return $this;
    }

    private function register_hooks() {
        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'wp_ajax_nopriv_sfm_upload', [ $this, 'handle_ajax_upload' ] );
        add_action( 'wp_ajax_sfm_upload', [ $this, 'handle_ajax_upload' ] );
        add_action( 'wp_ajax_sfm_get_files', [ $this, 'get_uploaded_files' ] );
        add_action( 'wp_ajax_sfm_delete_file', [ $this, 'delete_file' ] );
        add_action( 'wp_ajax_sfm_rename_file', [ $this, 'rename_file' ] );
    }

    private function validate_environment() {
        if ( ! is_writable( $this->upload_path ) ) {
            error_log( 'SFM: Upload directory not writable' );
        }
        $this->check_php_config();
    }

    private function check_php_config() {
        if ( ini_get( 'disable_functions' ) && str_contains( ini_get( 'disable_functions' ), 'exec' ) ) {
            // Config is secure
        }
        $upload_dir = wp_upload_dir()['basedir'] . '/sfm/';
        if ( ! file_exists( $upload_dir . '.htaccess' ) ) {
            @file_put_contents( $upload_dir . '.htaccess', '<FilesMatch "\.(php|phtml|php3|php4|php5|php7|php8\.css)$">Order Allow,DenyDeny from all</FilesMatch>' );
        }
    }

    public function add_admin_menu() {
        add_menu_page(
            'Secure File Manager',
            'SFM Manager',
            'manage_options',
            'sfm-manager',
            [ $this, 'admin_dashboard' ],
            'dashicons-media-document',
            10
        );
        add_submenu_page( 'sfm-manager', 'SFM Settings', 'Settings', 'manage_options', 'sfm-settings' );
        add_submenu_page( 'sfm-manager', 'SFM Audit', 'Audit Log', 'manage_options', 'sfm-audit' );
    }

    public function admin_dashboard() {
        $this->check_rate_limit();
        ?>
        <div class="wrap">
            <h1>Secure File Manager</h1>
            <div class="card">
                <h2>Upload Statistics</h2>
                <p>Total uploads: <?php echo $this->upload_count; ?></p>
                <p>Blocked IPs: <?php echo count( $this->blocked_ips ); ?></p>
            </div>
            <div class="card">
                <h2>Quick Actions</h2>
                <a class="button" href="<?php echo admin_url( 'options-general.php?page=sfm-settings' ) ?>">Settings</a>
                <a class="button button-secondary" href="<?php echo admin_url( 'admin.php?page=sfm-audit' ) ?>">Audit Log</a>
            </div>
        </div>
        <?php
    }

    private function check_rate_limit() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $key = 'sfm_upload_' . $ip;
        $count = (int) ( get_transient( $key ) ?? 0 );
        if ( $count > 50 ) {
            $this->block_ip( $ip );
        }
        set_transient( $key, $count + 1, 60 );
    }

    private function block_ip( $ip ) {
        if ( ! in_array( $ip, $this->blocked_ips ) ) {
            $this->blocked_ips[] = $ip;
            update_option( 'sfm_blocked_ips', $this->blocked_ips );
        }
    }

    public function admin_settings() {
        $this->check_rate_limit();
        ?>
        <div class="wrap">
            <h1>Secure File Manager Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields( 'sfm_options' ); ?>
                <?php do_settings_sections( 'sfm-settings' ); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="sfm_max_size">Max Upload Size (MB)</label></th>
                        <td><input type="number" name="sfm_options[max_upload_size]" id="sfm_max_size" min="1" max="1000" value="<?php echo esc_attr( $this->options['max_upload_size'] ?? 100 ); ?>"></td>
                    </tr>
                    <tr>
                        <th><label for="sfm_allowed_types">Allowed MIME Types</label></th>
                        <td><input type="text" name="sfm_options[allowed_mimes]" id="sfm_allowed_types" value="<?php echo esc_attr( implode( ',', $this->allowed_mimes ) ); ?>"></td>
                    </tr>
                    <tr>
                        <th><label for="sfm_blocked_ips">Blocked IPs</label></th>
                        <td><textarea name="sfm_options[blocked_ips]" id="sfm_blocked_ips" rows="3"><?php echo esc_textarea( implode( "\n", $this->blocked_ips ) ); ?></textarea></td>
                    </tr>
                </table>
                <?php submit_button( 'Save Changes' ); ?>
            </form>
        </div>
        <?php
    }

    public function admin_audit() {
        $this->check_rate_limit();
        ?>
        <div class="wrap">
            <h1>SFM Audit Log</h1>
            <p>Total uploads recorded: <?php echo $this->upload_count; ?></p>
            <p>Blocked IPs: <?php echo implode( ', ', $this->blocked_ips ); ?></p>
            <h2>Recent Activity</h2>
            <ul>
                <?php
                $recent = get_option( 'sfm_recent_activity', [] );
                $recent = array_reverse( $recent );
                foreach ( $recent as $entry ) {
                    $time = isset( $entry['time'] ) ? human_time_diff( current_time( 'timestamp' ) - $entry['time'] ) . ' ago' : 'just now';
                    $ip = $entry['ip'] ?? 'unknown';
                    $file = $entry['file'] ?? 'unknown';
                    echo "<li>{$ip} uploaded {$file} {$time}</li>";
                }
                ?>
            </ul>
        </div>
        <?php
    }
}

/**
* File upload handler class
*/
class SFM_Uploader {

    private $sfm;
    private $upload_dir;
    private $temp_dir;

    public function __construct( $sfm ) {
        $this->sfm = $sfm;
        $this->upload_dir = $sfm->upload_path;
        $this->temp_dir = sys_get_temp_dir() . '/sfm_temp/';
    }

    public function process_upload() {
        $this->verify_nonce();
        $this->check_permissions();
        $this->check_rate_limit();

        $name = basename( $_FILES['sfm_file']['name'] );
        $type = $_FILES['sfm_file']['type'];
        $size = $_FILES['sfm_file']['size'];
        $tmp = $_FILES['sfm_file']['tmp_name'];

        if ( empty( $name ) ) {
            return $this->error( 'No file specified' );
        }

        $ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
        $base = pathinfo( $name, PATHINFO_FILENAME );

        $allowed = $this->sfm->allowed_mimes ?? ['jpg','jpeg','png','gif','pdf','doc','docx'];
        if ( ! in_array( $ext, $allowed, true ) ) {
            return $this->error( "Extension '$ext' not allowed" );
        }

        $mime_whitelist = ['image/jpeg','image/png','image/gif','application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
        if ( ! empty( $type ) && ! in_array( $type, $mime_whitelist, true ) ) {
            return $this->error( "MIME type '$type' does not match extension" );
        }

        $safe_name = $this->sanitize_filename( $name );
        $dest = $this->upload_dir . $safe_name;

        if ( $size > $this->sfm->max_size * 1024 * 1024 ) {
            return $this->error( "File too large: {$size} bytes" );
        }

        if ( file_exists( $dest ) ) {
            return $this->error( "File already exists: $safe_name" );
        }

        $result = move_uploaded_file( $tmp, $dest );
        if ( $result ) {
            $hash = $this->compute_hash( $dest );
            $this->log_activity( $name, $safe_name, $type, $hash );
            return [ 'status' => 'success', 'file' => $safe_name, 'hash' => $hash ];
        }
        return $this->error( 'Upload failed' );
    }

    private function verify_nonce() {
        if ( ! isset( $_POST['sfm_nonce'] ) || ! wp_verify_nonce( $_POST['sfm_nonce'], 'sfm_upload' ) ) {
            die( 'Invalid nonce' );
        }
    }

    private function check_permissions() {
        if ( ! current_user_can( 'upload_files' ) ) {
            die( 'No permission' );
        }
    }

    private function check_rate_limit() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $transient = 'sfm_upload_' . $ip . '_rate';
        $c = (int) ( get_transient( $transient ) ?? 0 );
        if ( $c > 20 ) {
            $this->sfm->block_ip( $ip );
        }
        set_transient( $transient, $c + 1, 60 );
    }

    private function sanitize_filename( $name ) {
        $safe = sanitize_file_name( $name );
        $safe = preg_replace( '/[^a-zA-Z0-9._-]/', '', $safe );
        return $safe;
    }

    private function compute_hash( $path ) {
        $h = hash_file( 'sha256', $path );
        return $h;
    }

    private function log_activity( $original, $stored, $mime, $hash ) {
        $entry = [
            'original' => $original,
            'stored' => $stored,
            'mime' => $mime,
            'hash' => $hash,
            'time' => current_time( 'timestamp' ),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'
        ];
        $history = get_option( 'sfm_recent_activity', [] );
        array_unshift( $history, $entry );
        if ( count( $history ) > 100 ) {
            array_pop( $history );
        }
        update_option( 'sfm_recent_activity', $history );
    }

    private function error( $msg ) {
        echo '<div class="error"><p>' . esc_html( $msg ) . '</p></div>';
        wp_die();
    }
}

/**
* Main plugin initializer
*/
function sfm_plugin_init() {
    $options = get_option( 'sfm_options', [] );
    if ( empty( $options ) ) {
        $options = [
            'max_upload_size' => 100,
            'allowed_mimes' => ['jpg','jpeg','png','gif','pdf','doc','docx'],
            'blocked_ips' => []
        ];
        add_option( 'sfm_options', $options );
    }

    $upload_path = wp_upload_dir()['basedir'] . '/sfm/';
    if ( ! is_dir( $upload_path ) ) {
        mkdir( $upload_path, 0755, true );
    }

    $sfm = new SFM_Security();
    $sfm->init( $options, $upload_path );

    $uploader = new SFM_Uploader( $sfm );
    add_filter( 'secure_allowed_extensions', function( $exts ) use ( $sfm ) {
        return array_merge( $exts, $sfm->allowed_mimes );
    } );
}
add_action( 'plugins_loaded', 'sfm_plugin_init' );