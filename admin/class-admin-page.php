<?php
namespace SCML\UsersK7\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

use SCML\UsersK7\Includes\Logger;
use SCML\UsersK7\Includes\Settings;

/**
 * Handles the creation and rendering of the plugin's admin pages.
 */
class AdminPage {

    const PAGE_SLUG_MAIN_TOOL = 'usersk7-tool';
    const PAGE_SLUG_SETTINGS  = 'usersk7-settings';

    private $logger;
    private $settings;

    public function __construct(Logger $logger, Settings $settings) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function enqueue_admin_styles($hook_suffix) {
        $current_screen = get_current_screen();
        if (!$current_screen) {
            return;
        }
        $current_page_hook = $current_screen->id;

        // Hook for top-level page: 'toplevel_page_YOUR_MAIN_SLUG'
        // Hook for submenu page: 'YOUR_MAIN_SLUG_page_YOUR_SUBMENU_SLUG'
        $main_tool_hook = 'toplevel_page_' . self::PAGE_SLUG_MAIN_TOOL;
        $settings_hook = self::PAGE_SLUG_MAIN_TOOL . '_page_' . self::PAGE_SLUG_SETTINGS;


        if ( $current_page_hook === $main_tool_hook || $current_page_hook === $settings_hook ) {
            wp_enqueue_style(
                'usersk7-admin-style',
                USERSK7_PLUGIN_URL . 'assets/css/admin-style.css',
                [],
                defined('USERSK7_VERSION') ? USERSK7_VERSION : '1.0.0'
            );
        }
    }

    public function add_admin_menu_pages() {
        add_menu_page(
            __('UsersK7 User Sync', 'usersk7'),
            __('UsersK7', 'usersk7'),
            'manage_options',
            self::PAGE_SLUG_MAIN_TOOL,
            [$this, 'render_main_tool_page_content'],
            'dashicons-controls-play', // Choose your preferred Dashicon
            76 // Position in menu
        );

        add_submenu_page(
            self::PAGE_SLUG_MAIN_TOOL,
            __('UsersK7 Settings', 'usersk7'),
            __('Settings', 'usersk7'),
            'manage_options',
            self::PAGE_SLUG_SETTINGS,
            [$this, 'render_settings_page_content']
        );
    }

    public function render_main_tool_page_content() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'usersk7' ) );
        }

        $encryption_password_is_set = !empty($this->settings->get_encryption_password());
        ?>
        <div class="wrap usersk7-wrap">
            <h1>
                <span class="dashicons <?php echo $encryption_password_is_set ? 'dashicons-controls-play' : 'dashicons-lock'; ?>" style="font-size: 1.3em; margin-right: 5px; vertical-align: middle;"></span>
                <?php esc_html_e( 'UsersK7 - User Sync', 'usersk7' ); ?>
            </h1>

            <?php settings_errors('usersk7_messages'); ?>

            <?php if (!$encryption_password_is_set): ?>
                <div class="notice notice-warning notice-alt" style="margin-top:15px; margin-bottom:15px;">
                    <p>
                        <strong><?php esc_html_e('Encryption Password Not Set!', 'usersk7'); ?></strong>
                        <?php
                        printf(
                            wp_kses_post(__( 'You must set an encryption password in the <a href="%s">UsersK7 Settings</a> before you can export or import user data.', 'usersk7' )),
                            esc_url(admin_url('admin.php?page=' . self::PAGE_SLUG_SETTINGS))
                        );
                        ?>
                    </p>
                </div>
            <?php endif; ?>

            <p>
                <?php
                printf(
                    wp_kses_post( __( 'Configure encryption password and other options on the <a href="%s">UsersK7 Settings page</a>.', 'usersk7' ) ),
                    esc_url( admin_url( 'admin.php?page=' . self::PAGE_SLUG_SETTINGS ) )
                );
                ?>
            </p>
            <hr>

            <!-- Export Section -->
            <div id="usersk7-export-section" class="usersk7-section">
                <h2><?php esc_html_e( 'Record Users (Export)', 'usersk7' ); ?></h2>
                <p><?php esc_html_e( 'Click "Record" to generate an encrypted .k7 file containing all users and their data.', 'usersk7' ); ?></p>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                    <input type="hidden" name="action" value="usersk7_export_users">
                    <?php wp_nonce_field( 'usersk7_export_users_nonce', 'usersk7_export_nonce_field' ); ?>
                    <?php
                    submit_button(
                        __( 'Record Users to K7 File', 'usersk7' ),
                        'primary',
                        'submit_export_users',
                        true,
                        $encryption_password_is_set ? null : ['disabled' => 'disabled', 'title' => __('Please set an encryption password first.', 'usersk7')]
                    );
                    ?>
                </form>
                 <?php if (!$encryption_password_is_set): ?>
                    <p style="color: red; font-weight: bold;">
                        <?php esc_html_e('The export functionality is disabled until an encryption password is set.', 'usersk7'); ?>
                    </p>
                <?php endif; ?>
            </div>

            <hr class="usersk7-hr">

            <!-- Import Section -->
            <div id="usersk7-import-section" class="usersk7-section">
                <h2><?php esc_html_e( 'Load Users (Import)', 'usersk7' ); ?></h2>
                <p><?php esc_html_e( 'Select or drag your .k7 file into the "cassette deck" below to import or update users.', 'usersk7' ); ?></p>
                <form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="usersk7-import-form">
                    <input type="hidden" name="action" value="usersk7_import_users">
                    <?php wp_nonce_field( 'usersk7_import_users_nonce', 'usersk7_import_nonce_field' ); ?>

                    <div class="usersk7-import-box">
                        <img src="<?php echo esc_url(USERSK7_PLUGIN_URL . 'assets/images/radiocassette.png'); ?>" alt="<?php esc_attr_e('Radio Cassette Player Graphic', 'usersk7'); ?>" class="usersk7-cassette-graphic">
                        <label for="usersk7_import_file_input" class="usersk7-file-label">
                            <span><?php esc_html_e( 'Select or Drag .k7 file here', 'usersk7' ); ?></span>
                            <input type="file" id="usersk7_import_file_input" name="usersk7_import_file" accept=".k7" <?php echo $encryption_password_is_set ? 'required' : 'disabled title="' . esc_attr__('Please set an encryption password first to enable import.', 'usersk7') . '"'; ?>>
                        </label>
                        <p id="usersk7-file-name-display" style="text-align: center; margin-top: 10px; font-style: italic;"></p>
                    </div>

                    <p style="margin-top: 15px; margin-bottom: 10px;">
                        <label for="usersk7_dry_run_checkbox">
                            <input type="checkbox" name="usersk7_dry_run" id="usersk7_dry_run_checkbox" value="1">
                            <?php esc_html_e('Perform a Dry Run (Preview changes only, no actual data will be imported)', 'usersk7'); ?>
                        </label>
                    </p>

                    <?php
                    submit_button(
                        __( 'Load K7 and Import Users', 'usersk7' ),
                        'primary',
                        'submit_import_users',
                        true,
                        $encryption_password_is_set ? null : ['disabled' => 'disabled', 'title' => __('Please set an encryption password first.', 'usersk7')]
                    );
                    ?>
                </form>
                 <?php if (!$encryption_password_is_set): ?>
                    <p style="color: red; font-weight: bold;">
                        <?php esc_html_e('The import functionality is disabled until an encryption password is set.', 'usersk7'); ?>
                    </p>
                <?php endif; ?>

                <div class="usersk7-log-output" style="margin-top: 20px; padding: 10px; background: #f5f5f5; border: 1px solid #ddd; max-height: 300px; overflow-y: auto;">
                    <h3><?php esc_html_e('Last Import Log:', 'usersk7'); ?></h3>
                    <?php
                    $last_log_html = $this->logger->get_formatted_last_log();
                    echo $last_log_html ? $last_log_html : '<p>' . esc_html__('No import operations performed recently or logging is minimal.', 'usersk7') . '</p>';
                    ?>
                </div>
            </div>
        </div>
        <script type="text/javascript">
            document.addEventListener('DOMContentLoaded', function() {
                const fileInput = document.getElementById('usersk7_import_file_input');
                const fileNameDisplay = document.getElementById('usersk7-file-name-display');
                if (fileInput && fileNameDisplay) {
                    fileInput.addEventListener('change', function() {
                        if (this.files && this.files.length > 0) {
                            fileNameDisplay.textContent = '<?php echo esc_js(__('Selected file:', 'usersk7')); ?> ' + this.files[0].name;
                        } else {
                            fileNameDisplay.textContent = '';
                        }
                    });
                }
            });
        </script>
        <?php
    }

    public function render_settings_page_content() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'usersk7' ) );
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('UsersK7 Settings', 'usersk7'); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields(Settings::OPTION_GROUP);
                do_settings_sections(self::PAGE_SLUG_SETTINGS);
                submit_button(__('Save K7 Settings', 'usersk7'));
                ?>
            </form>
        </div>
        <?php
    }
}
?>