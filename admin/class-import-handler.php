<?php
namespace SCML\UsersK7\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

use SCML\UsersK7\Includes\EncryptionService;
use SCML\UsersK7\Includes\Logger;
use SCML\UsersK7\Includes\Settings; // To potentially check settings like "dry run" later

/**
 * Handles the user data import functionality.
 */
class ImportHandler {

    private $encryption_service;
    private $logger;
    private $settings; // For future options like "dry run"

    const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB limit for uploaded K7 file, adjust as needed

    /**
     * Constructor.
     * @param EncryptionService $encryption_service Instance of the encryption service.
     * @param Logger            $logger             Instance of the logger service.
     * @param Settings          $settings           Instance of the settings service.
     */
    public function __construct(EncryptionService $encryption_service, Logger $logger, Settings $settings) {
        $this->encryption_service = $encryption_service;
        $this->logger = $logger;
        $this->settings = $settings;
    }

    /**
     * Processes the import request triggered by the admin form.
     * Hooked to 'admin_post_usersk7_import_users'.
     */
    public function process_import_request() {
        $this->logger->clear_log(); // Clear previous log entries for this session
        $this->logger->add_entry(__('User import process initiated.', 'usersk7'), 'INFO');

        // 1. Security and Basic File Checks
        if ( ! isset( $_POST['usersk7_import_nonce_field'] ) || ! wp_verify_nonce( sanitize_key($_POST['usersk7_import_nonce_field']), 'usersk7_import_users_nonce' ) ) {
            $this->logger->add_entry(__('Security check failed (nonce) during import.', 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('Security check failed. Please try again.', 'usersk7'), 'nonce_failure');
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            $this->logger->add_entry(__('User without "manage_options" capability attempted import.', 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('You do not have sufficient permissions to import users.', 'usersk7'), 'permission_denied');
        }

        // Check if encryption password is set (needed for decryption)
        $encryption_password = $this->encryption_service->get_settings_encryption_password();
        if ( empty($encryption_password) ) {
            $this->logger->add_entry(__('Encryption password not set, cannot decrypt K7 file.', 'usersk7'), 'ERROR');
            $this->redirect_with_error(
                sprintf(
                    wp_kses_post(__('Encryption password is not set. Please set it in the <a href="%s">UsersK7 Settings</a> before importing.', 'usersk7')),
                    esc_url(admin_url('options-general.php?page=' . AdminPage::PAGE_SLUG_SETTINGS))
                ),
                'encryption_password_missing_import'
            );
        }

        if ( ! isset( $_FILES['usersk7_import_file'] ) || empty( $_FILES['usersk7_import_file']['name'] ) ) {
            $this->logger->add_entry(__('No import file was uploaded.', 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('No import file selected. Please choose a .k7 file to upload.', 'usersk7'), 'no_file_uploaded');
        }

        $file = $_FILES['usersk7_import_file'];

        if ( $file['error'] !== UPLOAD_ERR_OK ) {
            $this->logger->add_entry(__('File upload error: ' . $file['error'], 'usersk7'), 'ERROR');
            $this->redirect_with_error($this->get_upload_error_message($file['error']), 'upload_error_' . $file['error']);
        }

        // Validate file type (extension)
        $filename = sanitize_file_name($file['name']);
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if ( $file_extension !== 'k7' ) {
            $this->logger->add_entry(sprintf(__('Invalid file type uploaded: .%s. Expected .k7', 'usersk7'), $file_extension), 'ERROR');
            $this->redirect_with_error(__('Invalid file type. Please upload a .k7 file.', 'usersk7'), 'invalid_file_type');
        }

        // Validate file size
        if ( $file['size'] > self::MAX_FILE_SIZE ) {
            $this->logger->add_entry(sprintf(__('Uploaded file is too large: %s bytes. Max: %s bytes.', 'usersk7'), $file['size'], self::MAX_FILE_SIZE), 'ERROR');
            $this->redirect_with_error(sprintf(__('The uploaded file is too large. Maximum file size is %s.', 'usersk7'), size_format(self::MAX_FILE_SIZE)), 'file_too_large');
        }
        $this->logger->add_entry(sprintf(__('K7 file "%s" received for import.', 'usersk7'), $filename), 'INFO');

        // 2. Read and Process File Content
        $file_content_encoded = file_get_contents( $file['tmp_name'] );
        if ( $file_content_encoded === false || empty($file_content_encoded) ) {
            $this->logger->add_entry(__('Could not read uploaded K7 file or file is empty.', 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('Could not read the uploaded K7 file or it appears to be empty.', 'usersk7'), 'file_read_error');
        }

        // 3. Decrypt Data
        $gzipped_data = $this->encryption_service->decrypt( $file_content_encoded );
        if ( $gzipped_data === false ) {
            // EncryptionService should log specifics if it can
            $this->logger->add_entry(__('Failed to decrypt K7 file. Incorrect password or corrupted file?', 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('Could not decrypt the K7 file. Please ensure the encryption password is correct and the file is not corrupted.', 'usersk7'), 'decryption_failed');
        }
        $this->logger->add_entry(__('K7 file data successfully decrypted.', 'usersk7'), 'INFO');

        // 4. Decompress Data (GUnzip)
        $json_data = @gzdecode( $gzipped_data ); // Suppress errors initially, check return value
        if ( $json_data === false ) {
            $this->logger->add_entry(__('Failed to decompress K7 file data after decryption.', 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('Could not decompress the K7 file data. The file might be corrupted or not a valid K7 export.', 'usersk7'), 'decompression_failed');
        }
        $this->logger->add_entry(__('Decrypted data successfully GUnzipped.', 'usersk7'), 'INFO');

        // 5. Parse JSON
        $imported_users_data = json_decode( $json_data, true ); // true for associative array
        if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $imported_users_data ) ) {
            $this->logger->add_entry(__('Failed to parse JSON data from K7 file: ' . json_last_error_msg(), 'usersk7'), 'ERROR');
            $this->redirect_with_error(__('The K7 file does not contain valid user data (JSON parsing failed). It may be corrupted or not a UsersK7 export.', 'usersk7'), 'json_parse_error');
        }
        $this->logger->add_entry(sprintf(__('Successfully parsed JSON, found %d user entries.', 'usersk7'), count($imported_users_data)), 'INFO');

        // 6. Process Users (Create/Update)
        // Placeholder for Dry Run (Phase 3)
        // $is_dry_run = isset($_POST['usersk7_dry_run']) && $_POST['usersk7_dry_run'] === '1';
        // if ($is_dry_run) { $this->logger->add_entry('--- DRY RUN MODE ACTIVATED ---', 'INFO'); }

        $created_count = 0;
        $updated_count = 0;
        $skipped_count = 0;

        foreach ( $imported_users_data as $index => $user_data_from_file ) {
            $log_prefix = sprintf(__("Processing user entry #%d: ", 'usersk7'), $index + 1);

            if ( ! isset( $user_data_from_file['user_login'] ) ) {
                $this->logger->add_entry($log_prefix . __('Skipped - missing user_login.', 'usersk7'), 'WARNING');
                $skipped_count++;
                continue;
            }
            $user_login = sanitize_user( $user_data_from_file['user_login'], true );
            $log_prefix .= "{$user_login} - ";

            if ( ! isset( $user_data_from_file['user_pass'] ) ) {
                $this->logger->add_entry($log_prefix . __('Skipped - missing user_pass (hashed password).', 'usersk7'), 'WARNING');
                $skipped_count++;
                continue;
            }

            $existing_user = get_user_by( 'login', $user_login );

            // Prepare common user arguments for wp_insert_user / wp_update_user
            $user_args = [
                'user_login'      => $user_login,
                'user_pass'       => $user_data_from_file['user_pass'], // This IS the hashed password from export
                'user_email'      => isset($user_data_from_file['user_email']) ? sanitize_email($user_data_from_file['user_email']) : '',
                'user_url'        => isset($user_data_from_file['user_url']) ? esc_url_raw($user_data_from_file['user_url']) : '',
                'user_nicename'   => isset($user_data_from_file['user_nicename']) ? sanitize_title($user_data_from_file['user_nicename']) : sanitize_title($user_login),
                'display_name'    => isset($user_data_from_file['display_name']) ? sanitize_text_field($user_data_from_file['display_name']) : $user_login,
                'first_name'      => isset($user_data_from_file['first_name']) ? sanitize_text_field($user_data_from_file['first_name']) : '',
                'last_name'       => isset($user_data_from_file['last_name']) ? sanitize_text_field($user_data_from_file['last_name']) : '',
                'description'     => isset($user_data_from_file['description']) ? sanitize_textarea_field($user_data_from_file['description']) : '',
                'user_registered' => isset($user_data_from_file['user_registered']) ? $user_data_from_file['user_registered'] : gmdate('Y-m-d H:i:s'),
                // 'role' will be handled via user_meta_data ('wp_capabilities')
            ];

            $user_id_for_meta = null;

            if ( $existing_user ) {
                // Update existing user
                $user_args['ID'] = $existing_user->ID;
                // if ($is_dry_run) {
                //     $this->logger->add_entry($log_prefix . __('DRY RUN: Would update existing user.', 'usersk7'), 'INFO');
                //     $updated_count++;
                //     $user_id_for_meta = $existing_user->ID;
                // } else {
                    $result = wp_update_user( $user_args );
                    if ( is_wp_error( $result ) ) {
                        $this->logger->add_entry($log_prefix . sprintf(__('Error updating user: %s', 'usersk7'), $result->get_error_message()), 'ERROR');
                        $skipped_count++;
                    } else {
                        $this->logger->add_entry($log_prefix . __('Successfully updated existing user.', 'usersk7'), 'SUCCESS');
                        $updated_count++;
                        $user_id_for_meta = $existing_user->ID;
                    }
                // }
            } else {
                // Insert new user
                // if ($is_dry_run) {
                //     $this->logger->add_entry($log_prefix . __('DRY RUN: Would create new user.', 'usersk7'), 'INFO');
                //     $created_count++;
                //     // For dry run of meta, we'd need a placeholder ID or skip meta logging for new users.
                // } else {
                    $result = wp_insert_user( $user_args );
                    if ( is_wp_error( $result ) ) {
                        $this->logger->add_entry($log_prefix . sprintf(__('Error creating new user: %s', 'usersk7'), $result->get_error_message()), 'ERROR');
                        $skipped_count++;
                    } else {
                        $this->logger->add_entry($log_prefix . __('Successfully created new user (ID: %d).', 'usersk7'), $result, 'SUCCESS');
                        $created_count++;
                        $user_id_for_meta = $result; // New user ID
                    }
                // }
            }

            // Update user metadata if user was created/updated (or in dry run and we have an ID)
            if ( $user_id_for_meta && isset( $user_data_from_file['user_meta_data'] ) && is_array( $user_data_from_file['user_meta_data'] ) ) {
                $this->logger->add_entry($log_prefix . sprintf(__("Processing metadata for user ID %d...", 'usersk7'), $user_id_for_meta), 'INFO_DETAIL');

                // if ($is_dry_run) {
                //     foreach ( $user_data_from_file['user_meta_data'] as $meta_key => $meta_value ) {
                //         $this->logger->add_entry($log_prefix . sprintf(__('DRY RUN: Would update meta_key "%s".', 'usersk7'), $meta_key), 'INFO_DETAIL');
                //     }
                // } else {
                    // Clear existing roles before setting new ones for consistency, if wp_capabilities is present in import
                    if ( array_key_exists('wp_capabilities', $user_data_from_file['user_meta_data']) ) {
                        $user_to_update_roles = new \WP_User($user_id_for_meta);
                        if ($user_to_update_roles->exists()) {
                            $user_to_update_roles->set_role(''); // Clears all roles
                            $this->logger->add_entry($log_prefix . __('Cleared existing roles before applying imported ones.', 'usersk7'), 'INFO_DETAIL');
                        }
                    }

                    foreach ( $user_data_from_file['user_meta_data'] as $meta_key => $meta_value ) {
                        // The export process stores the actual value (unserialized if needed)
                        // wp_capabilities should be an array of roles/capabilities
                        // Other meta is typically a single string/value
                        update_user_meta( $user_id_for_meta, $meta_key, $meta_value );
                        // $this->logger->add_entry($log_prefix . sprintf(__('Updated meta_key "%s".', 'usersk7'), $meta_key), 'INFO_DETAIL');
                    }
                // }
            }
        } // end foreach user

        // 7. Finalize and Redirect
        $final_message = sprintf(
            __('K7 Import Complete. Users Created: %d, Users Updated: %d, Entries Skipped/Errored: %d.', 'usersk7'),
            $created_count,
            $updated_count,
            $skipped_count
        );
        // if ($is_dry_run) {
        //     $final_message = __('DRY RUN COMPLETED. ') . $final_message . __(' No actual changes were made.', 'usersk7');
        // }

        $this->logger->add_entry($final_message, 'SUCCESS');
        $this->logger->save_last_log(); // Save log to transient for display on next page

        add_settings_error('usersk7_messages', 'import_completed', $final_message, ($skipped_count > 0 ? 'warning' : 'updated'));
        wp_safe_redirect(admin_url('tools.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
        exit;
    }

    /**
     * Helper to redirect with an admin notice.
     * @param string $message The message for the notice.
     * @param string $code    A unique code for the error.
     * @param string $type    'error', 'warning', 'success', 'info'. Defaults to 'error'.
     */
    private function redirect_with_error($message, $code, $type = 'error') {
        $this->logger->save_last_log(); // Save any logs accumulated so far
        add_settings_error('usersk7_messages', esc_attr($code), $message, $type);
        wp_safe_redirect(admin_url('tools.php?page=' . AdminPage::PAGE_SLUG_MAIN_TOOL));
        exit;
    }

    /**
     * Get a user-friendly message for a PHP file upload error code.
     * @param int $error_code The PHP UPLOAD_ERR_* constant.
     * @return string The error message.
     */
    private function get_upload_error_message($error_code) {
        switch ($error_code) {
            case UPLOAD_ERR_INI_SIZE:
                return __('The uploaded file exceeds the upload_max_filesize directive in php.ini.', 'usersk7');
            case UPLOAD_ERR_FORM_SIZE:
                return __('The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form.', 'usersk7');
            case UPLOAD_ERR_PARTIAL:
                return __('The uploaded file was only partially uploaded.', 'usersk7');
            case UPLOAD_ERR_NO_FILE:
                return __('No file was uploaded.', 'usersk7'); // Should be caught earlier
            case UPLOAD_ERR_NO_TMP_DIR:
                return __('Missing a temporary folder on the server.', 'usersk7');
            case UPLOAD_ERR_CANT_WRITE:
                return __('Failed to write file to disk on the server.', 'usersk7');
            case UPLOAD_ERR_EXTENSION:
                return __('A PHP extension stopped the file upload.', 'usersk7');
            default:
                return __('An unknown file upload error occurred.', 'usersk7');
        }
    }
}
?>