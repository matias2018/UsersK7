<?php
namespace SCML\UsersK7\Includes; // Namespace declaration

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

/**
 * Handles plugin settings, registration, and retrieval.
 */
class Settings {

    const OPTION_GROUP = 'usersk7_settings_group'; // Unique group name for settings
    const OPTION_NAME  = 'usersk7_options';       // Name of the option array in wp_options table

    // Keys within the options array
    const KEY_ENCRYPTION_PASSWORD = 'encryption_password';
    const KEY_LOG_VERBOSITY       = 'log_verbosity'; // Example for future use
    const KEY_DELETE_AFTER_IMPORT = 'delete_after_import'; // Example for future use

    public function __construct() {
        // Constructor can be used if needed, but settings registration is hooked to admin_init
    }

    /**
     * Registers settings sections and fields using the WordPress Settings API.
     * Hooked to 'admin_init'.
     */
    public function register_plugin_settings() {
        register_setting(
            self::OPTION_GROUP,
            self::OPTION_NAME,
            [$this, 'sanitize_settings_input'] // Callback for sanitizing options
        );

        // --- Encryption Settings Section ---
        add_settings_section(
            'usersk7_encryption_settings_section',       // ID
            __('K7 Encryption Settings', 'usersk7'),    // Title
            [$this, 'render_encryption_section_info'],  // Callback for section description
            \SCML\UsersK7\Admin\AdminPage::PAGE_SLUG_SETTINGS // Page slug where this section appears
        );

        add_settings_field(
            self::KEY_ENCRYPTION_PASSWORD,                   // ID
            __('Encryption Password', 'usersk7'),        // Title
            [$this, 'render_encryption_password_field'], // Callback to render the field
            \SCML\UsersK7\Admin\AdminPage::PAGE_SLUG_SETTINGS, // Page slug
            'usersk7_encryption_settings_section'            // Section ID
        );

        // --- Logging Settings Section (Example for future) ---
        // add_settings_section(
        //     'usersk7_logging_settings_section',
        //     __('Logging Settings', 'usersk7'),
        //     [$this, 'render_logging_section_info'],
        //     \SCML\UsersK7\Admin\AdminPage::PAGE_SLUG_SETTINGS
        // );
        // add_settings_field( ... for log verbosity ... );
    }

    /**
     * Renders descriptive text for the encryption settings section.
     */
    public function render_encryption_section_info() {
        echo '<p>' . esc_html__('Define a strong, unique password here. This password will be used to encrypt the .k7 export files. You will need this same password on other sites to import (decrypt) these files.', 'usersk7') . '</p>';
        echo '<p><strong>' . esc_html__('Important: If you lose this password, you will not be able to decrypt previously exported files. Store it securely.', 'usersk7') . '</strong></p>';
    }

    /**
     * Renders the input field for the encryption password.
     */
    public function render_encryption_password_field() {
        $password = $this->get_encryption_password();
        printf(
            '<input type="password" id="%s" name="%s" value="%s" class="regular-text" autocomplete="new-password" />',
            esc_attr(self::KEY_ENCRYPTION_PASSWORD),
            esc_attr(self::OPTION_NAME . '[' . self::KEY_ENCRYPTION_PASSWORD . ']'),
            esc_attr($password)
        );
        echo '<p class="description">' . esc_html__('Minimum 8 characters recommended. Use a mix of uppercase, lowercase, numbers, and symbols.', 'usersk7') . '</p>';
    }

    /**
     * Sanitizes the settings input array before saving to the database.
     * @param array $input The array of settings values from the form.
     * @return array The sanitized array of settings values.
     */
    public function sanitize_settings_input($input) {
        $sanitized_input = array();

        if (isset($input[self::KEY_ENCRYPTION_PASSWORD])) {
            // Basic sanitization. For passwords, often just ensuring it's a string is enough,
            // as we don't want to alter it in ways that make it unusable.
            // More complex validation (e.g., strength) could happen here or client-side.
            $sanitized_input[self::KEY_ENCRYPTION_PASSWORD] = sanitize_text_field($input[self::KEY_ENCRYPTION_PASSWORD]);
        }

        // Sanitize other options as they are added
        // if (isset($input[self::KEY_LOG_VERBOSITY])) {
        //    $sanitized_input[self::KEY_LOG_VERBOSITY] = sanitize_key($input[self::KEY_LOG_VERBOSITY]);
        // }

        return $sanitized_input;
    }

    /**
     * Retrieves a specific option value from the plugin's options array.
     * @param string $key The key of the option to retrieve.
     * @param mixed $default The default value to return if the key is not found.
     * @return mixed The option value or the default.
     */
    public function get_setting($key, $default = false) {
        $options = get_option(self::OPTION_NAME, []); // Get all options or an empty array
        return isset($options[$key]) ? $options[$key] : $default;
    }

    /**
     * Specifically retrieves the encryption password.
     * @return string The encryption password, or an empty string if not set.
     */
    public function get_encryption_password() {
        return (string) $this->get_setting(self::KEY_ENCRYPTION_PASSWORD, '');
    }
}
?>