<?php
namespace SCML\UsersK7\Admin; // Namespace declaration

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

// Use statements for classes from other namespaces if you want to use short names
use SCML\UsersK7\Includes\Logger;
use SCML\UsersK7\Includes\Settings;

/**
 * Handles the creation and rendering of the plugin's admin pages.
 */
class AdminPage {

    const PAGE_SLUG_MAIN_TOOL = 'usersk7-tool';
    const PAGE_SLUG_SETTINGS  = 'usersk7-settings'; // Slug for the settings sub-page

    private $logger;
    private $settings;

    /**
     * Constructor.
     * @param Logger $logger The logger instance for displaying logs.
     * @param Settings $settings The settings instance.
     */
    public function __construct(Logger $logger, Settings $settings) {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    /**
     * Enqueues admin styles for the plugin's pages.
     * @param string $hook_suffix The hook suffix of the current admin page.
     */
    public function enqueue_admin_styles($hook_suffix) {
        $allowed_hooks = [
            'tools_page_' . self::PAGE_SLUG_MAIN_TOOL,
            'settings_page_' . self::PAGE_SLUG_SETTINGS,
        ];

        if ( ! in_array($hook_suffix, $allowed_hooks, true) ) {
            return;
        }

        wp_enqueue_style(
            'usersk7-admin-style',
            USERSK7_PLUGIN_URL . 'assets/css/admin-style.css',
            [], // Dependencies
            USERSK7_VERSION // Version for cache busting
        );
    }

    /**
     * Adds the admin menu pages for the plugin.
     * Hooked to 'admin_menu'.
     */
    public function add_admin_menu_pages() {
        // Main Tool Page (under "Tools")
        add_management_page(
            __('UsersK7 Tool', 'usersk7'),           // Page title
            __('UsersK7', 'usersk7'),                // Menu title
            'manage_options',                        // Capability required
            self::PAGE_SLUG_MAIN_TOOL,               // Menu slug
            [$this, 'render_main_tool_page_content'] // Callback to render the page
        );

        // Settings Sub-Page (under "Settings")
        add_options_page(
            __('UsersK7 Settings', 'usersk7'),       // Page title
            __('UsersK7', 'usersk7'),                // Menu title
            'manage_options',                        // Capability required
            self::PAGE_SLUG_SETTINGS,                // Menu slug
            [$this, 'render_settings_page_content']  // Callback to render the page
        );
    }

    /**
     * Renders the content for the main UsersK7 tool page.
     */
    public function render_main_tool_page_content() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'usersk7' ) );
        }
        ?>
        <div class="wrap usersk7-wrap">
            <h1>
                <span class="dashicons dashicons-controls-play" style="font-size: 1.3em; margin-right: 5px; vertical-align: middle;"></span>
                <?php esc_html_e( 'UsersK7 - User Sync', 'usersk7' ); ?>
            </h1>

            <?php settings_errors('usersk7_messages'); // Display admin notices for import/export results ?>

            <p>
                <?php
                printf(
                    wp_kses_post( __( 'Configure encryption password and other options on the <a href="%s">UsersK7 Settings page</a>.', 'usersk7' ) ),
                    esc_url( admin_url( 'options-general.php?page=' . self::PAGE_SLUG_SETTINGS ) )
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
                    <?php submit_button( __( 'Record Users to K7 File', 'usersk7' ), 'primary', 'submit_export_users' ); ?>
                </form>
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
                            <input type="file" id="usersk7_import_file_input" name="usersk7_import_file" accept=".k7" required>
                        </label>
                        <p id="usersk7-file-name-display" style="text-align: center; margin-top: 10px; font-style: italic;"></p>
                    </div>
                    <?php
                        // Example: Add a "Dry Run" checkbox later (Phase 3)
                        // echo '<p><label><input type="checkbox" name="usersk7_dry_run" value="1"> ' . esc_html__('Perform a Dry Run (Preview changes only)', 'usersk7') . '</label></p>';
                    ?>
                    <?php submit_button( __( 'Load K7 and Import Users', 'usersk7' ), 'primary', 'submit_import_users' ); ?>
                </form>

                <div class="usersk7-log-output" style="margin-top: 20px; padding: 10px; background: #f5f5f5; border: 1px solid #ddd; max-height: 300px; overflow-y: auto;">
                    <h3><?php esc_html_e('Last Import Log:', 'usersk7'); ?></h3>
                    <?php
                    // The logger should store the last log in a transient to display here
                    $last_log_html = $this->logger->get_formatted_last_log(); // Assume Logger class has this method
                    echo $last_log_html ? $last_log_html : '<p>' . esc_html__('No import operations performed recently or logging is minimal.', 'usersk7') . '</p>';
                    ?>
                </div>
            </div>
        </div>
        <script type="text/javascript">
            // Basic script to show selected file name
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

    /**
     * Renders the content for the UsersK7 settings page.
     */
    public function render_settings_page_content() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'usersk7' ) );
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('UsersK7 Settings', 'usersk7'); ?></h1>
            <form method="post" action="options.php">
                <?php
                // WordPress core functions for settings pages
                settings_fields(Settings::OPTION_GROUP); // Output nonce, action, and option_page fields
                do_settings_sections(self::PAGE_SLUG_SETTINGS); // Prints out all settings sections added to this page
                submit_button(__('Save K7 Settings', 'usersk7'));
                ?>
            </form>
        </div>
        <?php
    }
}
?>