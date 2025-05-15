<?php
namespace SCML\UsersK7\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

use SCML\UsersK7\Includes\EncryptionService;
use SCML\UsersK7\Includes\Logger;

/**
 * Handles the user data export functionality.
 */
class ExportHandler {

    private $encryption_service;
    private $logger;

    /**
     * Constructor.
     * @param EncryptionService $encryption_service Instance of the encryption service.
     * @param Logger $logger Instance of the logger service.
     */
    public function __construct(EncryptionService $encryption_service, Logger $logger) {
        $this->encryption_service = $encryption_service;
        $this->logger = $logger;
    }

    /**
     * Processes the export request triggered by the admin form.
     * Hooked to 'admin_post_usersk7_export_users'.
     */
    public function process_export_request() {
        // 1. Security Checks
        if ( ! isset( $_POST['usersk7_export_nonce_field'] ) || ! wp_verify_nonce( sanitize_key($_POST['usersk7_export_nonce_field']), 'usersk7_export_users_nonce' ) ) {
            $this->logger->add_entry(__('Security check failed (nonce) during export.', 'usersk7'), 'ERROR');
            // Saving log for admin display is tricky here as we might wp_die or redirect.
            // For now, this log entry is mostly for server-side logging if configured.
            wp_die( esc_html__( 'Security check failed. Please try again.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 403 ) );
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            $this->logger->add_entry(__('User without "manage_options" capability attempted export.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'You do not have sufficient permissions to export users.', 'usersk7' ), esc_html__( 'Permission Denied', 'usersk7' ), array( 'response' => 403 ) );
        }

        // Check if encryption password is set
        $encryption_password = $this->encryption_service->get_settings_encryption_password(); // Assume EncryptionService has this getter or gets it from Settings directly
        if ( empty($encryption_password) ) {
             // This message should ideally be shown on the previous page.
             // Redirecting back with an error message is better than wp_die here.
            add_settings_error(
                'usersk7_messages',
                'encryption_password_missing',
                sprintf(
                    wp_kses_post(__('Encryption password is not set. Please set it in the <a href="%s">UsersK7 Settings</a> before exporting.', 'usersk7')),
                    esc_url(admin_url('options-general.php?page=' . AdminPage::PAGE_SLUG_SETTINGS))
                ),
                'error'
            );
            // Redirect back to the tool page
            wp_safe_redirect(admin_url('tools.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
            exit;
        }


        $this->logger->add_entry(__('User export process started.', 'usersk7'), 'INFO');

        // 2. Fetch User Data
        $users_export_array = [];
        $wp_users = get_users( [
            'fields'  => 'all_with_meta', // Gets WP_User objects with their meta pre-fetched
            'orderby' => 'ID',
            'order'   => 'ASC',
        ] );

        if ( empty($wp_users) ) {
            $this->logger->add_entry(__('No users found to export.', 'usersk7'), 'WARNING');
            // Redirect back with a notice
            add_settings_error('usersk7_messages', 'no_users_to_export', __('No users found on this site to export.', 'usersk7'), 'info');
            wp_safe_redirect(admin_url('tools.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
            exit;
        }

        foreach ( $wp_users as $user_obj ) {
            $user_data = $user_obj->to_array(); // Converts WP_User object to an array

            // Ensure essential fields are present, especially user_pass
            if ( ! isset( $user_data['user_pass'] ) ) {
                $this->logger->add_entry(sprintf(__('User %s (ID: %d) is missing user_pass field. Skipping critical data.', 'usersk7'), $user_obj->user_login, $user_obj->ID), 'WARNING');
                // Continue, but this user might not import correctly if password is required.
            }

            // Get all user meta data
            $all_meta = get_user_meta( $user_obj->ID );
            $processed_meta = [];
            if ( ! empty( $all_meta ) ) {
                foreach ( $all_meta as $meta_key => $meta_value_array ) {
                    // get_user_meta returns an array of values for each key. Usually, it's a single-element array.
                    // We want to store the actual value, not an array containing the value, unless it's genuinely an array (like capabilities).
                    $value_to_store = (count($meta_value_array) === 1) ? $meta_value_array[0] : $meta_value_array;

                    // Special handling for 'wp_capabilities' - ensure it's unserialized
                    if ( $meta_key === 'wp_capabilities' && is_string($value_to_store) ) {
                        $caps = @unserialize($value_to_store);
                        if ($caps !== false) {
                            $value_to_store = $caps;
                        } else {
                             $this->logger->add_entry(sprintf(__('Could not unserialize wp_capabilities for user %s (ID: %d).', 'usersk7'), $user_obj->user_login, $user_obj->ID), 'WARNING');
                        }
                    }
                    $processed_meta[$meta_key] = $value_to_store;
                }
            }
            $user_data['user_meta_data'] = $processed_meta; // Add meta to the user's data array
            $users_export_array[] = $user_data;
        }
        $this->logger->add_entry(sprintf(__('Fetched data for %d users.', 'usersk7'), count($users_export_array)), 'INFO');

        // 3. Serialize to JSON
        $json_data = wp_json_encode( $users_export_array, JSON_PRETTY_PRINT ); // Using wp_json_encode for WP context
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            $this->logger->add_entry(__('Error encoding user data to JSON: ' . json_last_error_msg(), 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Fatal Error: Could not create JSON data for export.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        $this->logger->add_entry(__('User data successfully encoded to JSON.', 'usersk7'), 'INFO');

        // 4. Compress Data (Gzip)
        $gzipped_data = gzencode( $json_data, 9 ); // Max compression level
        if ( $gzipped_data === false ) {
            $this->logger->add_entry(__('Error Gzipping user data.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Fatal Error: Could not compress data for export.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        $this->logger->add_entry(__('JSON data successfully GZipped.', 'usersk7'), 'INFO');

        // 5. Encrypt Data
        $encrypted_data_with_iv = $this->encryption_service->encrypt( $gzipped_data );
        if ( $encrypted_data_with_iv === false ) {
            // EncryptionService should log specific error if it can
            $this->logger->add_entry(__('Fatal error during data encryption.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Fatal Error: Could not encrypt data for export. Check encryption settings and server OpenSSL support.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        $this->logger->add_entry(__('GZipped data successfully encrypted.', 'usersk7'), 'INFO');

        // 6. Trigger Download
        $filename = 'Usersk7_' . date( 'Ymd_His' ) . '.k7';

        // Clear any previously sent headers or output buffer
        if (headers_sent()) {
            $this->logger->add_entry(__('Headers already sent before attempting to send K7 file. Export failed.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Error: Cannot send file because output has already started. Check for errors or unexpected output from other plugins/themes.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        // If output buffering is active, clean it.
        if (ob_get_level() > 0) {
            ob_end_clean();
        }

        header( 'Content-Description: File Transfer' );
        header( 'Content-Type: application/octet-stream' ); // Indicate binary file
        header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
        header( 'Content-Transfer-Encoding: binary' );
        header( 'Expires: 0' );
        header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0' );
        header( 'Pragma: public' );
        header( 'Content-Length: ' . strlen( $encrypted_data_with_iv ) ); // Length of the final binary data

        // Output the data directly
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- This is binary file data
        echo $encrypted_data_with_iv;

        $this->logger->add_entry(sprintf(__('K7 file "%s" successfully generated and sent for download.', 'usersk7'), $filename), 'SUCCESS');
        // Log saving would typically happen via a shutdown hook if we want to capture this success message for admin display,
        // as exit() prevents further execution in this script. For now, server-side logging is the primary target.
        exit;
    }
}
?>