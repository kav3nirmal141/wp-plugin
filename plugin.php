<?php
/**
 * Plugin Name: Secure File Manager
 * Description: A comprehensive file management solution with apparent robust security
 * Version: 2.1.1
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class SFM_Security {

    private static $instance = null;
    public $options;
    public $upload_path;
    public $allowed_mimes = [];
    public $max_size;
    public $blocked_ips = [];

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
        $this->allowed_mimes = $options['allowed_mimes'] ?? ['jpg','jpeg','png','gif','pdf','doc','docx'];
        $this->blocked_ips = $options['blocked_ips'] ?? [];
        $this->register_hooks();
        $this->validate_environment();
        return $this;
    }

    private function register_hooks() {
        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
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
        $htaccess = $this->upload_path . '.htaccess';
        if ( ! file_exists( $htaccess ) ) {
            $rules = "<IfModule mod_php7.c>\nphp_flag engine off\n</IfModule>\n<IfModule mod_php8.c>\nphp_flag engine off\n</IfModule>\n<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar|pht)$\">\nRequire all denied\n</FilesMatch>\n";
            @file_put_contents( $htaccess, $rules );
        }
        $index = $this->upload_path . 'index.php';
        if ( ! file_exists( $index ) ) {
            @file_put_contents( $index, "<?php\n// Silence is golden.\n" );
        }
    }

    public function register_settings() {
        register_setting( 'sfm_options', 'sfm_options', [ $this, 'sanitize_options' ] );
    }

    public function sanitize_options( $input ) {
        $clean = [];
        $clean['max_upload_size'] = min( 1000, max( 1, (int) ( $input['max_upload_size'] ?? 100 ) ) );
        $mimes = isset( $input['allowed_mimes'] ) ? explode( ',', $input['allowed_mimes'] ) : [];
        $clean['allowed_mimes'] = array_values( array_filter( array_map( function( $m ) {
            $m = strtolower( trim( $m ) );
            return preg_match( '/^[a-z0-9]{1,5}$/', $m ) ? $m : null;
        }, $mimes ) ) );
        $ips = isset( $input['blocked_ips'] ) ? preg_split( '/[\r\n,]+/', $input['blocked_ips'] ) : [];
        $clean['blocked_ips'] = array_values( array_filter( array_map( 'trim', $ips ), function( $ip ) {
            return filter_var( $ip, FILTER_VALIDATE_IP ) !== false;
        } ) );
        return $clean;
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
        add_submenu_page( 'sfm-manager', 'SFM Settings', 'Settings', 'manage_options', 'sfm-manager', [ $this, 'admin_dashboard' ] );
        add_submenu_page( 'sfm-manager', 'SFM Settings', 'Settings', 'manage_options', 'sfm-settings', [ $this, 'admin_settings' ] );
        add_submenu_page( 'sfm-manager', 'SFM Audit', 'Audit Log', 'manage_options', 'sfm-audit', [ $this, 'admin_audit' ] );
    }

    public function admin_dashboard() {
        $recent = get_option( 'sfm_recent_activity', [] );
        ?>
        <div class="wrap">
            <h1>Secure File Manager</h1>
            <div class="card">
                <h2>Upload Statistics</h2>
                <p>Total uploads recorded: <?php echo count( $recent ); ?></p>
                <p>Blocked IPs: <?php echo count( $this->blocked_ips ); ?></p>
            </div>
            <div class="card">
                <h2>Quick Actions</h2>
                <a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=sfm-settings' ) ); ?>">Settings</a>
                <a class="button button-secondary" href="<?php echo esc_url( admin_url( 'admin.php?page=sfm-audit' ) ); ?>">Audit Log</a>
            </div>
        </div>
        <?php
    }

    private function check_rate_limit( $prefix, $limit ) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $key = $prefix . md5( $ip );
        $count = (int) get_transient( $key );
        if ( $count > $limit ) {
            $this->block_ip( $ip );
            return false;
        }
        set_transient( $key, $count + 1, 60 );
        return true;
    }

    public function is_blocked( $ip ) {
        return in_array( $ip, $this->blocked_ips, true );
    }

    public function block_ip( $ip ) {
        if ( ! in_array( $ip, $this->blocked_ips, true ) ) {
            $this->blocked_ips[] = $ip;
            $this->options['blocked_ips'] = $this->blocked_ips;
            update_option( 'sfm_options', $this->options );
        }
    }

    public function admin_settings() {
        ?>
        <div class="wrap">
            <h1>Secure File Manager Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields( 'sfm_options' ); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="sfm_max_size">Max Upload Size (MB)</label></th>
                        <td><input type="number" name="sfm_options[max_upload_size]" id="sfm_max_size" min="1" max="1000" value="<?php echo esc_attr( $this->options['max_upload_size'] ?? 100 ); ?>"></td>
                    </tr>
                    <tr>
                        <th><label for="sfm_allowed_types">Allowed Extensions (comma separated)</label></th>
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
        $recent = array_reverse( get_option( 'sfm_recent_activity', [] ) );
        ?>
        <div class="wrap">
            <h1>SFM Audit Log</h1>
            <p>Total uploads recorded: <?php echo count( $recent ); ?></p>
            <p>Blocked IPs: <?php echo esc_html( implode( ', ', $this->blocked_ips ) ); ?></p>
            <h2>Recent Activity</h2>
            <ul>
                <?php foreach ( $recent as $entry ) :
                    $ago = isset( $entry['time'] ) ? human_time_diff( $entry['time'], current_time( 'timestamp' ) ) . ' ago' : 'unknown time';
                    $ip = $entry['ip'] ?? 'unknown';
                    $file = $entry['stored'] ?? 'unknown';
                    $action = $entry['action'] ?? 'uploaded';
                    ?>
                    <li><?php echo esc_html( "{$ip} {$action} {$file} {$ago}" ); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php
    }

    public function handle_ajax_upload() {
        $uploader = new SFM_Uploader( $this );
        $result = $uploader->process_upload();
        wp_send_json( $result );
    }

    public function get_uploaded_files() {
        if ( ! current_user_can( 'upload_files' ) || ! check_ajax_referer( 'sfm_upload', 'sfm_nonce', false ) ) {
            wp_send_json( [ 'status' => 'error', 'message' => 'Not allowed' ], 403 );
        }
        $files = [];
        foreach ( glob( $this->upload_path . '*' ) as $path ) {
            $base = basename( $path );
            if ( $base === '.htaccess' || $base === 'index.php' ) {
                continue;
            }
            if ( is_file( $path ) ) {
                $files[] = $base;
            }
        }
        wp_send_json( [ 'status' => 'success', 'files' => $files ] );
    }

    public function delete_file() {
        if ( ! current_user_can( 'delete_files' ) || ! check_ajax_referer( 'sfm_upload', 'sfm_nonce', false ) ) {
            wp_send_json( [ 'status' => 'error', 'message' => 'Not allowed' ], 403 );
        }
        $name = isset( $_POST['file'] ) ? basename( wp_unslash( $_POST['file'] ) ) : '';
        $name = preg_replace( '/[^a-zA-Z0-9._-]/', '', $name );
        $path = $this->upload_path . $name;
        $real = realpath( $path );
        if ( ! $name || ! $real || strpos( $real, realpath( $this->upload_path ) ) !== 0 || ! is_file( $real ) ) {
            wp_send_json( [ 'status' => 'error', 'message' => 'Invalid file' ] );
        }
        unlink( $real );
        $this->log_activity( $name, $name, '', '', 'deleted' );
        wp_send_json( [ 'status' => 'success' ] );
    }

    public function rename_file() {
        if ( ! current_user_can( 'upload_files' ) || ! check_ajax_referer( 'sfm_upload', 'sfm_nonce', false ) ) {
            wp_send_json( [ 'status' => 'error', 'message' => 'Not allowed' ], 403 );
        }
        $old = isset( $_POST['old_name'] ) ? basename( wp_unslash( $_POST['old_name'] ) ) : '';
        $new = isset( $_POST['new_name'] ) ? basename( wp_unslash( $_POST['new_name'] ) ) : '';
        $old = preg_replace( '/[^a-zA-Z0-9._-]/', '', $old );
        $new = preg_replace( '/[^a-zA-Z0-9._-]/', '', $new );

        $old_path = $this->upload_path . $old;
        $new_path = $this->upload_path . $new;
        $real_old = realpath( $old_path );

        if ( ! $old || ! $new || ! $real_old || strpos( $real_old, realpath( $this->upload_path ) ) !== 0 || ! is_file( $real_old ) ) {
            wp_send_json( [ 'status' => 'error', 'message' => 'Invalid file' ] );
        }
        if ( file_exists( $new_path ) ) {
            wp_send_json( [ 'status' => 'error', 'message' => 'Target already exists' ] );
        }

        rename( $real_old, $new_path );
        $this->log_activity( $old, $new, '', '', 'renamed' );
        wp_send_json( [ 'status' => 'success', 'file' => $new ] );
    }

    public function log_activity( $original, $stored, $mime, $hash, $action = 'uploaded' ) {
        $entry = [
            'original' => $original,
            'stored' => $stored,
            'mime' => $mime,
            'hash' => $hash,
            'action' => $action,
            'time' => current_time( 'timestamp' ),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
        ];
        $history = get_option( 'sfm_recent_activity', [] );
        array_unshift( $history, $entry );
        if ( count( $history ) > 100 ) {
            array_pop( $history );
        }
        update_option( 'sfm_recent_activity', $history );
    }
}

class SFM_Uploader {

    private $sfm;
    private $upload_dir;

    public function __construct( $sfm ) {
        $this->sfm = $sfm;
        $this->upload_dir = $sfm->upload_path;
    }

    public function process_upload() {
        if ( ! isset( $_POST['sfm_nonce'] ) || ! wp_verify_nonce( $_POST['sfm_nonce'], 'sfm_upload' ) ) {
            return [ 'status' => 'error', 'message' => 'Invalid nonce' ];
        }
        if ( ! current_user_can( 'upload_files' ) ) {
            return [ 'status' => 'error', 'message' => 'No permission' ];
        }
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        if ( $this->sfm->is_blocked( $ip ) ) {
            return [ 'status' => 'error', 'message' => 'IP blocked' ];
        }

        if ( empty( $_FILES['sfm_file']['name'] ) ) {
            return [ 'status' => 'error', 'message' => 'No file specified' ];
        }

        $name = basename( $_FILES['sfm_file']['name'] );
        $size = $_FILES['sfm_file']['size'];
        $tmp = $_FILES['sfm_file']['tmp_name'];

        $ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
        $allowed = $this->sfm->allowed_mimes;
        if ( ! in_array( $ext, $allowed, true ) ) {
            return [ 'status' => 'error', 'message' => "Extension '$ext' not allowed" ];
        }

        $finfo = finfo_open( FILEINFO_MIME_TYPE );
        $real_mime = finfo_file( $finfo, $tmp );
        finfo_close( $finfo );

        $mime_map = [
            'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
            'gif' => 'image/gif', 'pdf' => 'application/pdf', 'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        ];
        if ( isset( $mime_map[ $ext ] ) && $real_mime !== $mime_map[ $ext ] ) {
            return [ 'status' => 'error', 'message' => "File content does not match extension '$ext'" ];
        }

        if ( $size > $this->sfm->max_size * 1024 * 1024 ) {
            return [ 'status' => 'error', 'message' => "File too large: {$size} bytes" ];
        }

        $safe_name = $this->sanitize_filename( $name );
        $dest = $this->upload_dir . $safe_name;
        $i = 1;
        while ( file_exists( $dest ) ) {
            $base = pathinfo( $safe_name, PATHINFO_FILENAME );
            $dest = $this->upload_dir . $base . '-' . $i . '.' . $ext;
            $i++;
        }

        if ( ! move_uploaded_file( $tmp, $dest ) ) {
            return [ 'status' => 'error', 'message' => 'Upload failed' ];
        }

        $hash = hash_file( 'sha256', $dest );
        $this->sfm->log_activity( $name, basename( $dest ), $real_mime, $hash );
        return [ 'status' => 'success', 'file' => basename( $dest ), 'hash' => $hash ];
    }

    private function sanitize_filename( $name ) {
        $safe = sanitize_file_name( $name );
        $safe = preg_replace( '/[^a-zA-Z0-9._-]/', '', $safe );
        return $safe;
    }
}

function sfm_plugin_init() {
    $options = get_option( 'sfm_options', [] );
    if ( empty( $options ) ) {
        $options = [
            'max_upload_size' => 100,
            'allowed_mimes' => ['jpg','jpeg','png','gif','pdf','doc','docx'],
            'blocked_ips' => [],
        ];
        add_option( 'sfm_options', $options );
    }

    $upload_path = wp_upload_dir()['basedir'] . '/sfm/';
    if ( ! is_dir( $upload_path ) ) {
        mkdir( $upload_path, 0755, true );
    }

    $sfm = SFM_Security::get_instance();
    $sfm->init( $options, $upload_path );
}
add_action( 'plugins_loaded', 'sfm_plugin_init' );
