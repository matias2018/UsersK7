<?php
namespace SCML\UsersK7\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

use SCML\UsersK7\Includes\EncryptionService;
use SCML\UsersK7\Includes\Logger;
// Assuming AdminPage class is in the same namespace or use statement is added if different
// use SCML\UsersK7\Admin\AdminPage;

/**
 * Handles the user data export functionality.
 */
class ExportHandler {

    private $encryption_service;
    private $logger;

    public function __construct(EncryptionService $encryption_service, Logger $logger) {
        $this->encryption_service = $encryption_service;
        $this->logger = $logger;
    }

    public function process_export_request() {
        $this->logger->clear_log(); // Good practice to clear for a new operation
        $this->logger->add_entry(__('User export process started.', 'usersk7'), 'INFO');

        if ( ! isset( $_POST['usersk7_export_nonce_field'] ) || ! wp_verify_nonce( sanitize_key($_POST['usersk7_export_nonce_field']), 'usersk7_export_users_nonce' ) ) {
            $this->logger->add_entry(__('Security check failed (nonce) during export.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Security check failed. Please try again.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 403 ) );
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            $this->logger->add_entry(__('User without "manage_options" capability attempted export.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'You do not have sufficient permissions to export users.', 'usersk7' ), esc_html__( 'Permission Denied', 'usersk7' ), array( 'response' => 403 ) );
        }

        $encryption_password = $this->encryption_service->get_settings_encryption_password();
        if ( empty($encryption_password) ) {
            $this->logger->add_entry(__('Export failed: Encryption password is not set.', 'usersk7'), 'ERROR');
            $this->logger->save_last_log(); // Save log before redirecting
            add_settings_error(
                'usersk7_messages',
                'encryption_password_missing_export',
                sprintf(
                    wp_kses_post(__('Encryption password is not set. Please set it in the <a href="%s">UsersK7 Settings</a> before exporting.', 'usersk7')),
                    esc_url(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_SETTINGS))
                ),
                'error'
            );
            wp_safe_redirect(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
            exit;
        }

        $users_export_array = [];
        $wp_users = get_users( [
            'fields'  => 'all_with_meta',
            'orderby' => 'ID',
            'order'   => 'ASC',
        ] );

        if ( empty($wp_users) ) {
            $this->logger->add_entry(__('No users found to export.', 'usersk7'), 'WARNING');
            $this->logger->save_last_log();
            add_settings_error('usersk7_messages', 'no_users_to_export', __('No users found on this site to export.', 'usersk7'), 'info');
            wp_safe_redirect(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
            exit;
        }

        foreach ( $wp_users as $user_obj ) {
            $user_data = $user_obj->to_array();
            if ( ! isset( $user_data['user_pass'] ) ) {
                $this->logger->add_entry(sprintf(__('User %s (ID: %d) is missing user_pass field. This might cause issues on import.', 'usersk7'), $user_obj->user_login, $user_obj->ID), 'WARNING');
            }

            $all_meta = get_user_meta( $user_obj->ID );
            $processed_meta = [];
            if ( ! empty( $all_meta ) ) {
                foreach ( $all_meta as $meta_key => $meta_value_array ) {
                    $value_to_store = (count($meta_value_array) === 1) ? $meta_value_array[0] : $meta_value_array;
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
            $user_data['user_meta_data'] = $processed_meta;
            $users_export_array[] = $user_data;
        }
        $this->logger->add_entry(sprintf(__('Fetched data for %d users.', 'usersk7'), count($users_export_array)), 'INFO');

        $json_data = wp_json_encode( $users_export_array, JSON_PRETTY_PRINT );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            $this->logger->add_entry(__('Error encoding user data to JSON: ' . json_last_error_msg(), 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Fatal Error: Could not create JSON data for export.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        $this->logger->add_entry(__('User data successfully encoded to JSON.', 'usersk7'), 'INFO');

        $gzipped_data = gzencode( $json_data, 9 );
        if ( $gzipped_data === false ) {
            $this->logger->add_entry(__('Error Gzipping user data.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Fatal Error: Could not compress data for export.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        $this->logger->add_entry(__('JSON data successfully GZipped.', 'usersk7'), 'INFO');

        $encrypted_data_with_iv = $this->encryption_service->encrypt( $gzipped_data );
        if ( $encrypted_data_with_iv === false ) {
            $this->logger->add_entry(__('Fatal error during data encryption. Check OpenSSL support and password.', 'usersk7'), 'ERROR');
            wp_die( esc_html__( 'Fatal Error: Could not encrypt data for export. Check encryption settings and server OpenSSL support.', 'usersk7' ), esc_html__( 'Export Error', 'usersk7' ), array( 'response' => 500 ) );
        }
        $this->logger->add_entry(__('GZipped data successfully encrypted.', 'usersk7'), 'INFO');

        $filename = 'UsersK7_' . date( 'Ymd_His' ) . '.k7'; // Changed filename

        if (headers_sent($file, $line)) {
            $this->logger->add_entry(sprintf(__('Headers already sent by %s at line %s before attempting to send K7 file. Export failed.', 'usersk7'), $file, $line), 'ERROR');
            // Log this error to be visible if possible
            $this->logger->save_last_log();
            add_settings_error('usersk7_messages', 'headers_sent_export', __('Error: Cannot send file because output has already started. Check for errors or unexpected output from other plugins/themes.', 'usersk7'), 'error');
            wp_safe_redirect(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
            exit;
        }
        if (ob_get_level() > 0) {
            ob_end_clean();
        }

        header( 'Content-Description: File Transfer' );
        header( 'Content-Type: application/octet-stream' );
        header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
        header( 'Content-Transfer-Encoding: binary' );
        header( 'Expires: 0' );
        header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0' );
        header( 'Pragma: public' );
        header( 'Content-Length: ' . strlen( $encrypted_data_with_iv ) );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo $encrypted_data_with_iv;

        $this->logger->add_entry(sprintf(__('K7 file "%s" successfully generated and sent for download.', 'usersk7'), $filename), 'SUCCESS');
        // Cannot save log to transient here as exit() stops execution. Server-side log is primary.
        exit;
    }
}
?>