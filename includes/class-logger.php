<?php
namespace SCML\UsersK7\Includes;

class Logger {
    private $settings;
    private $log_entries = [];
    const TRANSIENT_LAST_LOG = 'usersk7_last_import_log';

    public function __construct(Settings $settings) { $this->settings = $settings; }
    public function add_entry($message, $type = 'INFO') { $this->log_entries[] = "[$type] " . date('Y-m-d H:i:s') . " - " . $message; }
    public function get_log_entries() { return $this->log_entries; }
    public function clear_log() { $this->log_entries = []; }
    public function save_last_log() { set_transient(self::TRANSIENT_LAST_LOG, $this->log_entries, HOUR_IN_SECONDS); }
    public function get_formatted_last_log() {
        $log = get_transient(self::TRANSIENT_LAST_LOG);
        if (empty($log) || !is_array($log)) return '';
        return '<ul style="list-style: none; padding-left: 0;"><li>' . implode('</li><li>', array_map('esc_html', $log)) . '</li></ul>';
    }
}
?>