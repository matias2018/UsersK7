<?php
namespace SCML\UsersK7\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

use SCML\UsersK7\Includes\EncryptionService;
use SCML\UsersK7\Includes\Logger;
use SCML\UsersK7\Includes\Settings;
// use SCML\UsersK7\Admin\AdminPage; // For constants if needed for redirects

/**
 * Handles the user data import functionality.
 */
class ImportHandler {

    private $encryption_service;
    private $logger;
    private $settings;

    const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB limit, adjust as needed

    public function __construct(EncryptionService $encryption_service, Logger $logger, Settings $settings) {
        $this->encryption_service = $encryption_service;
        $this->logger = $logger;
        $this->settings = $settings;
    }

    public function process_import_request() {
        $this->logger->clear_log();
        $this->logger->add_entry(__('User import process initiated.', 'usersk7'), 'INFO');

        if ( ! isset( $_POST['usersk7_import_nonce_field'] ) || ! wp_verify_nonce( sanitize_key($_POST['usersk7_import_nonce_field']), 'usersk7_import_users_nonce' ) ) {
            $this->redirect_with_error(__('Security check failed (nonce) during import.', 'usersk7'), 'nonce_failure_import');
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            $this->redirect_with_error(__('You do not have sufficient permissions to import users.', 'usersk7'), 'permission_denied_import');
        }

        $encryption_password = $this->encryption_service->get_settings_encryption_password();
        if ( empty($encryption_password) ) {
            $this->redirect_with_error(
                sprintf(
                    wp_kses_post(__('Encryption password is not set. Please set it in the <a href="%s">UsersK7 Settings</a> before importing.', 'usersk7')),
                    esc_url(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_SETTINGS))
                ),
                'encryption_password_missing_import'
            );
        }

        if ( ! isset( $_FILES['usersk7_import_file'] ) || empty( $_FILES['usersk7_import_file']['name'] ) ) {
            $this->redirect_with_error(__('No import file selected. Please choose a .k7 file to upload.', 'usersk7'), 'no_file_uploaded_import');
        }

        $file = $_FILES['usersk7_import_file'];

        if ( $file['error'] !== UPLOAD_ERR_OK ) {
            $this->redirect_with_error($this->get_upload_error_message($file['error']), 'upload_error_import_' . $file['error']);
        }

        $filename = sanitize_file_name($file['name']);
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if ( $file_extension !== 'k7' ) {
            $this->redirect_with_error(__('Invalid file type. Please upload a .k7 file.', 'usersk7'), 'invalid_file_type_import');
        }

        if ( $file['size'] > self::MAX_FILE_SIZE ) {
            $this->redirect_with_error(sprintf(__('The uploaded file is too large. Maximum file size is %s.', 'usersk7'), size_format(self::MAX_FILE_SIZE)), 'file_too_large_import');
        }
        $this->logger->add_entry(sprintf(__('K7 file "%s" received for import.', 'usersk7'), $filename), 'INFO');

        $file_content_encoded = file_get_contents( $file['tmp_name'] );
        if ( $file_content_encoded === false || empty($file_content_encoded) ) {
            $this->redirect_with_error(__('Could not read the uploaded K7 file or it appears to be empty.', 'usersk7'), 'file_read_error_import');
        }

        $gzipped_data = $this->encryption_service->decrypt( $file_content_encoded );
        if ( $gzipped_data === false ) {
            $this->redirect_with_error(__('Could not decrypt the K7 file. Please ensure the encryption password is correct and the file is not corrupted.', 'usersk7'), 'decryption_failed_import');
        }
        $this->logger->add_entry(__('K7 file data successfully decrypted.', 'usersk7'), 'INFO');

        $json_data = @gzdecode( $gzipped_data );
        if ( $json_data === false ) {
            $this->redirect_with_error(__('Could not decompress the K7 file data. The file might be corrupted or not a valid K7 export.', 'usersk7'), 'decompression_failed_import');
        }
        $this->logger->add_entry(__('Decrypted data successfully GUnzipped.', 'usersk7'), 'INFO');

        $imported_users_data = json_decode( $json_data, true );
        if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $imported_users_data ) ) {
            $this->redirect_with_error(__('The K7 file does not contain valid user data (JSON parsing failed). It may be corrupted or not a UsersK7 export.', 'usersk7'), 'json_parse_error_import');
        }
        $this->logger->add_entry(sprintf(__('Successfully parsed JSON, found %d user entries.', 'usersk7'), count($imported_users_data)), 'INFO');

        $is_dry_run = isset($_POST['usersk7_dry_run']) && sanitize_key($_POST['usersk7_dry_run']) === '1';
        if ($is_dry_run) {
            $this->logger->add_entry('--- DRY RUN MODE ACTIVATED ---', null, 'INFO_IMPORTANT');
        }

        $created_count = 0;
        $updated_count = 0;
        $skipped_count = 0;
        $new_user_temp_id_counter = -1;

        foreach ( $imported_users_data as $index => $user_data_from_file ) {
            // Define the current user login for logging early, handle if missing
            $current_user_login_for_log = isset($user_data_from_file['user_login']) ? sanitize_user($user_data_from_file['user_login'], true) : 'LOGIN_MISSING';
            $entry_identifier_for_log = sprintf("#%d (%s)", $index + 1, $current_user_login_for_log); // e.g., "#1 (boss)"

            if ( ! isset( $user_data_from_file['user_login'] ) ) {
                $this->logger->add_entry(sprintf(__('Processing user entry %s: Skipped - missing user_login.', 'usersk7'), $entry_identifier_for_log), null, 'WARNING');
                $skipped_count++;
                continue;
            }

            // user_login is now guaranteed to be set
            $user_login = sanitize_user( $user_data_from_file['user_login'], true );

            if ( ! isset( $user_data_from_file['user_pass'] ) && !$is_dry_run ) {
                $this->logger->add_entry(sprintf(__('Processing user entry %s: Skipped - missing user_pass (hashed password).', 'usersk7'), $entry_identifier_for_log), null, 'WARNING');
                $skipped_count++;
                continue;
            }

            $existing_user = get_user_by( 'login', $user_login );

            $user_args = [ /* ... (as before, prepare user_args) ... */ ];
            // Ensure user_pass is set in user_args even for dry run if you need to log it or something, otherwise it can be null if not checked above
            $user_args['user_pass'] = $user_data_from_file['user_pass'] ?? null;


            $user_id_for_meta = null;

            if ( $existing_user ) {
                $user_args['ID'] = $existing_user->ID;
                $user_id_for_meta = $existing_user->ID;

                if ($is_dry_run) {
                    $this->logger->add_entry(sprintf(__('Processing user entry %s: DRY RUN - Would update existing user (ID: %d).', 'usersk7'), $entry_identifier_for_log, $existing_user->ID), null, 'INFO');
                    $updated_count++;
                } else {
                    $result = wp_update_user( $user_args );
                    if ( is_wp_error( $result ) ) {
                        $this->logger->add_entry(sprintf(__('Processing user entry %s: Error updating user - %s', 'usersk7'), $entry_identifier_for_log, $result->get_error_message()), null, 'ERROR');
                        $skipped_count++;
                        $user_id_for_meta = null;
                    } else {
                        $this->logger->add_entry(sprintf(__('Processing user entry %s: Successfully updated existing user.', 'usersk7'), $entry_identifier_for_log), null, 'SUCCESS');
                        $updated_count++;
                    }
                }
            } else { // New user
                if ($is_dry_run) {
                    $this->logger->add_entry(sprintf(__('Processing user entry %s: DRY RUN - Would create new user.', 'usersk7'), $entry_identifier_for_log), null, 'INFO');
                    $created_count++;
                    $user_id_for_meta = $new_user_temp_id_counter--;
                } else {
                    $result = wp_insert_user( $user_args );
                    if ( is_wp_error( $result ) ) {
                        $this->logger->add_entry(sprintf(__('Processing user entry %s: Error creating new user - %s', 'usersk7'), $entry_identifier_for_log, $result->get_error_message()), null, 'ERROR');
                        $skipped_count++;
                        $user_id_for_meta = null;
                    } else {
                        $this->logger->add_entry(sprintf(__('Processing user entry %s: Successfully created new user (ID: %d).', 'usersk7'), $entry_identifier_for_log, $result), null, 'SUCCESS');
                        $created_count++;
                        $user_id_for_meta = $result;
                    }
                }
            }

            if ( $user_id_for_meta !== null && isset( $user_data_from_file['user_meta_data'] ) && is_array( $user_data_from_file['user_meta_data'] ) ) {
                $meta_log_id_display = $user_id_for_meta < 0 ? 'NEW_DRY_RUN_USER' : $user_id_for_meta;
                
                if ($is_dry_run) {
                    foreach ( $user_data_from_file['user_meta_data'] as $meta_key => $meta_value ) {
                        $this->logger->add_entry(sprintf(__('Processing user entry %s (Meta for User ID %s): DRY RUN - Would set/update meta_key "%s".', 'usersk7'), $entry_identifier_for_log, $meta_log_id_display, esc_html($meta_key)), null, 'INFO_DETAIL');
                    }
                } else { // Actual import, not dry run
                    if ( array_key_exists('wp_capabilities', $user_data_from_file['user_meta_data']) ) {
                        $user_to_update_roles = new \WP_User($user_id_for_meta);
                        if ($user_to_update_roles->exists()) {
                            $user_to_update_roles->set_role('');
                            $this->logger->add_entry(sprintf(__('Processing user entry %s (Meta for User ID %s): Cleared existing roles before applying imported ones.', 'usersk7'), $entry_identifier_for_log, $meta_log_id_display), null, 'INFO_DETAIL');
                        }
                    }
                    foreach ( $user_data_from_file['user_meta_data'] as $meta_key => $meta_value ) {
                        update_user_meta( $user_id_for_meta, $meta_key, $meta_value );
                         // Optional: $this->logger->add_entry(sprintf(__('Processing user entry %s (Meta for User ID %s): Set/Updated meta_key "%s".', 'usersk7'), $entry_identifier_for_log, $meta_log_id_display, esc_html($meta_key)), null, 'INFO_DETAIL');
                    }
                }
            }
        } // end foreach user

        $final_message_body = sprintf(
            __('Users Created: %d, Users Updated: %d, Entries Skipped/Errored: %d.', 'usersk7'),
            $created_count,
            $updated_count,
            $skipped_count
        );

        $final_message_prefix = $is_dry_run ? __('DRY RUN COMPLETED. ', 'usersk7') : __('K7 Import Complete. ', 'usersk7');
        $final_message_suffix = $is_dry_run ? __(' No actual changes were made to the database.', 'usersk7') : '';
        $final_message = $final_message_prefix . $final_message_body . $final_message_suffix;

        $log_type = $is_dry_run ? 'INFO_IMPORTANT' : ($skipped_count > 0 ? 'WARNING' : 'SUCCESS');
        $this->logger->add_entry($final_message, null, $log_type);

        $notice_type = $is_dry_run ? 'info' : ($skipped_count > 0 ? 'warning' : 'updated');
        add_settings_error('usersk7_messages', 'import_status', $final_message, $notice_type);

        $this->logger->save_last_log();
        wp_safe_redirect(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
        exit;
    }

    private function redirect_with_error($message, $code, $type = 'error') {
        $this->logger->add_entry(sprintf(__('Redirecting with error [%s]: %s', 'usersk7'), $code, $message), null, 'ERROR');
        $this->logger->save_last_log();
        add_settings_error('usersk7_messages', esc_attr($code), $message, $type);
        wp_safe_redirect(admin_url('admin.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
        exit;
    }

    private function get_upload_error_message($error_code) {
        switch ($error_code) {
            case UPLOAD_ERR_INI_SIZE: return __('The uploaded file exceeds the upload_max_filesize directive in php.ini.', 'usersk7');
            case UPLOAD_ERR_FORM_SIZE: return __('The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form.', 'usersk7');
            case UPLOAD_ERR_PARTIAL: return __('The uploaded file was only partially uploaded.', 'usersk7');
            case UPLOAD_ERR_NO_FILE: return __('No file was uploaded.', 'usersk7');
            case UPLOAD_ERR_NO_TMP_DIR: return __('Missing a temporary folder on the server.', 'usersk7');
            case UPLOAD_ERR_CANT_WRITE: return __('Failed to write file to disk on the server.', 'usersk7');
            case UPLOAD_ERR_EXTENSION: return __('A PHP extension stopped the file upload.', 'usersk7');
            default: return __('An unknown file upload error occurred.', 'usersk7');
        }
    }
}
?>