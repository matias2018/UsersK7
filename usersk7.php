<?php
/**
 * Plugin Name:       UsersK7
 * Description:       Export and Import WordPress users with encryption and K7 flair.
 * Version:           1.1.0
 * Author:            Pedro Matias
 * License:           GPLv2 or later
 * Text Domain:       usersk7
 * Namespace:         SCML\UsersK7
 */

// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'USERSK7_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'USERSK7_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'USERSK7_VERSION', '1.1.0' ); // Useful for cache busting assets

// Require the necessary class files
require_once USERSK7_PLUGIN_DIR . 'includes/class-settings.php';
require_once USERSK7_PLUGIN_DIR . 'includes/class-encryption-service.php';
require_once USERSK7_PLUGIN_DIR . 'includes/class-logger.php';
require_once USERSK7_PLUGIN_DIR . 'admin/class-admin-page.php';
require_once USERSK7_PLUGIN_DIR . 'admin/class-export-handler.php';
require_once USERSK7_PLUGIN_DIR . 'admin/class-import-handler.php';

// Later: require_once USERSK7_PLUGIN_DIR . 'cli/class-cli-commands.php';


/**
 * Main plugin class for UsersK7.
 * Acts as a loader and central point for initializing plugin components.
 */
class UsersK7_Plugin {

    private static $instance;

    public $settings;
    public $admin_page;
    public $export_handler;
    public $import_handler;
    public $encryption_service;
    public $logger;
    // public $cli_commands; // To be added in a later phase

    /**
     * Ensures only one instance of the plugin class is loaded.
     * @return UsersK7_Plugin
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor to prevent direct instantiation.
     * Initializes services and registers hooks.
     */
    private function __construct() {
        $this->init_services();
        $this->register_hooks();
    }

    /**
     * Initializes the core services (classes) of the plugin.
     */
    private function init_services() {
        // Order matters for dependencies
        $this->settings           = new \SCML\UsersK7\Includes\Settings();
        $this->encryption_service = new \SCML\UsersK7\Includes\EncryptionService($this->settings); // Depends on Settings
        $this->logger             = new \SCML\UsersK7\Includes\Logger($this->settings); // Might depend on settings (e.g., log level)
        $this->admin_page         = new \SCML\UsersK7\Admin\AdminPage($this->logger, $this->settings); // Depends on Logger, Settings
        $this->export_handler     = new \SCML\UsersK7\Admin\ExportHandler($this->encryption_service, $this->logger); // Depends on Encryption, Logger
        $this->import_handler     = new \SCML\UsersK7\Admin\ImportHandler($this->encryption_service, $this->logger, $this->settings); // Depends on Encryption, Logger, Settings

        // Initialize CLI commands if WP_CLI is active (Phase 2)
        // if ( defined( 'WP_CLI' ) && WP_CLI ) {
        //     require_once USERSK7_PLUGIN_DIR . 'cli/class-cli-commands.php';
        //     $this->cli_commands = new \SCML\UsersK7\CLI\CLI_Commands($this->encryption_service, $this->logger, $this->settings);
        // }
    }

    /**
     * Registers WordPress hooks for the plugin.
     */
    private function register_hooks() {
        // Admin menu and settings registration
        add_action( 'admin_menu', [$this->admin_page, 'add_admin_menu_pages'] );
        add_action( 'admin_init', [$this->settings, 'register_plugin_settings'] );

        // Enqueue styles for plugin admin pages
        add_action( 'admin_enqueue_scripts', [$this->admin_page, 'enqueue_admin_styles'] );

        // Handlers for form submissions (Export/Import actions)
        add_action( 'admin_post_usersk7_export_users', [$this->export_handler, 'process_export_request'] );
        add_action( 'admin_post_usersk7_import_users', [$this->import_handler, 'process_import_request'] );

        // Register WP-CLI commands (Phase 2)
        // if ( $this->cli_commands ) {
        //     \WP_CLI::add_command( 'usersk7', $this->cli_commands );
        // }
    }
}

/**
 * Begins execution of the plugin.
 */
function usersk7_initialize_plugin() {
    return UsersK7_Plugin::get_instance();
}
// Get the plugin running.
usersk7_initialize_plugin();

?>