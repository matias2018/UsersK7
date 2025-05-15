<?php
namespace SCML\UsersK7\Includes;

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

/**
 * Handles encryption and decryption of user data.
 */
class EncryptionService {

    private $settings;
    private const ENCRYPTION_METHOD = 'aes-256-cbc'; // Recommended encryption method

    /**
     * Constructor.
     * @param Settings $settings Instance of the Settings service.
     */
    public function __construct(Settings $settings) {
        $this->settings = $settings;
    }

    /**
     * Retrieves the encryption password from the plugin settings.
     *
     * @return string The encryption password, or an empty string if not set.
     */
    public function get_settings_encryption_password(): string {
        return $this->settings->get_encryption_password(); // Delegate to the Settings class
    }

    /**
     * Encrypts the given data.
     *
     * @param string $data The raw data to encrypt (e.g., gzipped JSON string).
     * @return string|false The base64 encoded string (IV + ciphertext) on success, or false on failure.
     */
    public function encrypt(string $data) {
        $password = $this->get_settings_encryption_password();
        if (empty($password)) {
            // Optionally, log this error or let the calling function handle it.
            // For now, ExportHandler checks this, so we proceed assuming password is provided by this point.
            // error_log('UsersK7 Encryption Error: Password not set.'); // Example server log
            return false;
        }

        if (!extension_loaded('openssl')) {
            // error_log('UsersK7 Encryption Error: OpenSSL extension is not loaded.');
            // This should ideally be checked earlier, e.g., on plugin activation or settings page.
            return false;
        }

        $iv_length = openssl_cipher_iv_length(self::ENCRYPTION_METHOD);
        if ($iv_length === false) {
            // error_log('UsersK7 Encryption Error: Could not get IV length for ' . self::ENCRYPTION_METHOD);
            return false;
        }
        $iv = openssl_random_pseudo_bytes($iv_length);
        if ($iv === false) {
            // error_log('UsersK7 Encryption Error: Could not generate IV.');
            return false;
        }

        $ciphertext = openssl_encrypt($data, self::ENCRYPTION_METHOD, $password, OPENSSL_RAW_DATA, $iv);
        // OPENSSL_RAW_DATA is important so we get raw binary, not base64 which we do ourselves later.

        if ($ciphertext === false) {
            // error_log('UsersK7 Encryption Error: openssl_encrypt failed. Error: ' . openssl_error_string());
            return false;
        }

        // Prepend IV to ciphertext, then base64 encode
        return base64_encode($iv . $ciphertext);
    }

    /**
     * Decrypts the given data.
     *
     * @param string $base64_encoded_data_with_iv The base64 encoded string (IV + ciphertext).
     * @return string|false The raw decrypted data on success, or false on failure.
     */
    public function decrypt(string $base64_encoded_data_with_iv) {
        $password = $this->get_settings_encryption_password();
        if (empty($password)) {
            // error_log('UsersK7 Decryption Error: Password not set.');
            return false;
        }

        if (!extension_loaded('openssl')) {
            // error_log('UsersK7 Decryption Error: OpenSSL extension is not loaded.');
            return false;
        }

        $decoded_data = base64_decode($base64_encoded_data_with_iv, true); // Strict mode for base64
        if ($decoded_data === false) {
            // error_log('UsersK7 Decryption Error: base64_decode failed. Input might not be valid base64.');
            return false;
        }

        $iv_length = openssl_cipher_iv_length(self::ENCRYPTION_METHOD);
        if ($iv_length === false || strlen($decoded_data) < $iv_length) {
            // error_log('UsersK7 Decryption Error: Could not get IV length or decoded data is too short.');
            return false;
        }

        $iv = substr($decoded_data, 0, $iv_length);
        $ciphertext = substr($decoded_data, $iv_length);

        if (empty($ciphertext)) {
            // error_log('UsersK7 Decryption Error: Ciphertext is empty after extracting IV.');
            return false;
        }

        $decrypted_data = openssl_decrypt($ciphertext, self::ENCRYPTION_METHOD, $password, OPENSSL_RAW_DATA, $iv);

        if ($decrypted_data === false) {
            // This is a common point of failure if password is wrong or data is corrupt (MAC check fails)
            // error_log('UsersK7 Decryption Error: openssl_decrypt failed. Error: ' . openssl_error_string());
            return false;
        }

        return $decrypted_data;
    }
}
?>