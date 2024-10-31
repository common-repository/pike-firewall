<?php
/*
 * Plugin Name: Pike Firewall
 * Plugin URI: http://pike.hqpeak.com
 * Description: Block Tor, Proxy, Cloud/Hosting/VPN, Country originating traffic e.g. anonymous/fraudelent traffic, IDS for wordpress and crawlers verification/monitoring 
 * Version: 1.4.1
 * Author: HQPeak
 * Author URI: http://hqpeak.com
 * License: GPL2
 */

/*  Copyright 2016  HQPeak  (email: contact@hqpeak.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

if ( !defined('ABSPATH') )	die();	// Exit if accessed directly

if ( !defined('PIKEFIREWALL_DIR') )	define('PIKEFIREWALL_DIR', plugin_dir_path( __FILE__ ));	// Plugin root directory path
if ( !defined('PIKEFIREWALL_VERSION') )	define('PIKEFIREWALL_VERSION', '1.4.1');	// Plugin version

// Get some globals used throughout the plugin... 
$pike_settings = pike_default_settings();
$pike_tables = pike_all_tables();
$pike_vendors = pike_get_vendors();
$pike_ip = pike_get_ip_address();
$pike_agent = pike_get_user_agent();

// Run the plugin
pike_firewall_run();

/**
 *  Default settings
 *  
 *  @return void
 */
function pike_default_settings() {
	return array(
		'version'				=> PIKEFIREWALL_VERSION,
		'update_progress'		=> 'no',
		'stomp_with_me'			=> time(),
		'services_update_time'	=> time(),
		'crawlers_update_time'	=> time(),
		'default_tor'			=> array('url' => 'http://pike.hqpeak.com/api/tor', 'enable' => ''),
		'default_proxy'			=> array('url' => 'http://pike.hqpeak.com/api/proxy', 'enable' => ''),
		'default_range'			=> array('url' => 'http://pike.hqpeak.com/api/range', 'enable' => ''),
		'default_crawlers'		=> array('url' => 'http://pike.hqpeak.com/api/bot', 'enable' => ''),
		'check'					=> array('visit' => ''),
		'deny'					=> '',
		'custom_msg'			=> array('text' => pike_custom_message_text(), 'enable' => ''),
		'whitelist'				=> '',
		'file_scan'				=> array('time' => '', 'interval' => '1', 'interval_unit' => 'days', 'directory' => ''),
		'send_email'			=> array('type' => 'email', 'recipient' => '') 
	);
}

/** 
 * Default message template: shown when user is blocked
 * 
 * @return string
 */
function pike_custom_message_text() {
	ob_start();
?>
<p style="font-weight:bold; text-align:center;">
	[pike_firewall_logo]
	<br/>
	[ip_address]
</p>
<?php
	$content = ob_get_contents();
	ob_end_clean();
	return $content;
}

/**
 * Database tables used by the plugin; Given in a 'key => value' format
 * 
 * @return void
 */ 
function pike_all_tables() {
	global $wpdb;
	return array(
		'single_ip' 		=> $wpdb->prefix.'pike_firewall_single_ip',
		'range_ip' 			=> $wpdb->prefix.'pike_firewall_range_ip',
		'crawl_ip' 			=> $wpdb->prefix.'pike_firewall_crawl_ip',
		'crawl_range_ip' 	=> $wpdb->prefix.'pike_firewall_crawl_range_ip',
		'crawl_fake_ip' 	=> $wpdb->prefix.'pike_firewall_crawl_fake_ip',
		'log' 				=> $wpdb->prefix.'pike_firewall_log',
		'log_crawlers' 		=> $wpdb->prefix.'pike_firewall_log_crawlers',
		'filesystem_scan'	=> $wpdb->prefix.'pike_firewall_filesystem_scan',
		'login'				=> $wpdb->prefix.'pike_firewall_login',
	);
}

/** 
 * Vendors for verified crawlers check
 * 
 * @return void
 */
function pike_get_vendors() {
	return array(
		'1'	=> 'google',
		'2'	=> 'bing',
		'3'	=> 'yahoo',
		'4'	=> 'yandex',
		'5'	=> 'facebook'
	);
}

/**
 * Get the user IP address
 * 
 * @return string
 */ 
function pike_get_ip_address() {
	$pike_ip = "";
	if ( isset($_SERVER['REMOTE_ADDR']) ) {
		$pike_ip = $_SERVER['REMOTE_ADDR'];
	}
	if ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) ) {
		$pike_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	}
	return $pike_ip;
}

/**
 * Get the User-Agent
 * 
 * @return string
 */ 
function pike_get_user_agent() {
	$pike_agent = "";
	if ( isset($_SERVER['HTTP_USER_AGENT']) ) {
		$pike_agent = $_SERVER['HTTP_USER_AGENT'];
	}
	return $pike_agent;
}

/** 
 * Initial plugin function
 * 
 * @return void
 */
function pike_firewall_run() {	
	global $pike_settings, $pike_ip;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	add_action('admin_head', 'pike_admin_header');
	add_action('admin_init', 'pike_register_plugin_settings');
	add_action('admin_menu', 'pike_add_admin_menu');
	
	add_action('admin_enqueue_scripts', 'pike_admin_scripts_init');	
	add_action('wp_enqueue_scripts', 'pike_frontend_scripts_init');
	
	add_action('wp_ajax_pike_firewall_ajax', 'pike_ajax_scan');
	add_action('wp_ajax_nopriv_pike_firewall_ajax', 'pike_ajax_scan');
	add_action('wp_ajax_pike_firewall_ajax_filescan', 'pike_ajax_filescan');
	add_action('wp_ajax_pike_firewall_ajax_cron_reset', 'pike_ajax_cron_reset');
		
	add_action('plugins_loaded', 'pike_update_plugin');
		
	add_action('init', 'pike_csrf_protect', 1);
	add_action('init', 'pike_convert_to_csv', 8);
		
	add_action('update_option_pike_firewall', 'pike_cron_scan');
	add_action('hourly_update_event', 'pike_cron_job');
	add_action('fs_update_event', 'pike_cron_job_filescan');
	
	add_action('wp_login_failed', 'pike_login_failed');
	add_action('wp_login', 'pike_login_success', 10, 2);
	
	add_filter('cron_schedules', 'pike_cron_add_time');

	// Check for whitelisted IP address
	$white_check = false;
	if ( is_array($pike_options) && sizeof($pike_options) > 0 ) {
		$whitelist = ( !empty($pike_options['whitelist']) ) ? explode(',', $pike_options['whitelist']) : array(); 
		foreach ( $whitelist as $wl ) {
			if ( $pike_ip == trim($wl) ) {
				$white_check = true;
				break;
			}
		}
	}
	
	if ( !$white_check ) {
		add_action('init', 'pike_stealth_mode', 1);
		add_action('init', 'pike_show_captcha', 4);
		
		add_action('init', 'pike_block_crawlers');
		
		add_action('init', 'pike_read_public_content');
		add_action('init', 'pike_send_comment');
		add_action('init', 'pike_user_subscription');
		add_action('init', 'pike_deny_post_requests');
		add_action('init', 'pike_deny_all_requests');
		
		add_action('init', 'pike_foreign_request', 15);
		add_action('init', 'pike_user_agent', 15);
		add_action('init', 'pike_user_enumeration', 15);
		add_action('init', 'pike_proxy_headers', 15);		
		
		add_action('register_post', 'pike_user_registration');
		add_action('wp_authenticate', 'pike_admin_dashboard_access');
		add_action('admin_init', 'pike_admin_dashboard_access');
		add_action('widgets_init', 'pike_register_widget');
	}		
	
	// Activate/Deactivate the plugin
	register_activation_hook(__FILE__, 'pike_install');
	register_activation_hook(__FILE__, 'pike_install_data');
	register_deactivation_hook(__FILE__, 'pike_uninstall');
}

/** 
 * Register the plugin settings
 * 
 * @return void
 */
function pike_register_plugin_settings() {
	register_setting('pike_firewall', 'pike_firewall', 'pike_validate_settings');
	add_settings_section('main_section', 'General Settings', 'pike_create_section', __FILE__);
}

/** 
 * Settings validation (no validation)
 * 
 * @param array $plugin_options The plugin settings
 * 
 * @return void
 */
function pike_validate_settings($plugin_options) {
	return $plugin_options;
}

/**
 * Settings sections (empty)
 * 
 * @return void
 */ 
function pike_create_section() { }

/**
 * Add the settings menu
 * 
 * @return void
 */ 
function pike_add_admin_menu() {
	add_menu_page( __('Pike Firewall Settings'), __('Pike Firewall'), 'manage_options', 'pike_firewall', 'pike_add_menu_options', 'dashicons-shield', 68 );
}

/**
 * Settings page
 * 
 * @return void
 */ 
function pike_add_menu_options() {
	if ( !current_user_can('manage_options') )  {
		wp_die( __('You do not have sufficient permissions to access this page.') );
	}
		
	global $wpdb, $pike_settings, $pike_tables;
	$pike_options = get_option('pike_firewall', $pike_settings);	
		
	// Initialize and instantiate Table classes for wordpress-styled tables
	if ( !class_exists('WP_List_Table_Copy') ) {
		require_once PIKEFIREWALL_DIR.'classes/class-wp-list-table-copy.php';
	}
	
	if ( !class_exists('Pike_Firewall_Logs_Table') ) {
		require_once PIKEFIREWALL_DIR.'classes/class-pike-firewall-logs-table.php';
	}
	$table_logs = new Pike_Firewall_Logs_Table();
		
	// Get the active tab
	$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : 'main';
?>
	<div class="wrap">
		<h1>Pike Firewall Settings</h1> 
		<?php settings_errors(); ?>
		<p><a href="<?php echo esc_url('https://wordpress.org/plugins/pike-firewall/') ?>" target="_blank"><strong>Plugin page</strong></a></p>
			
		<h2 class="nav-tab-wrapper">
			<a href="<?php echo esc_url('?page=pike_firewall&tab=main') ?>" class="nav-tab <?php echo $active_tab == 'main' ? 'nav-tab-active' : ''; ?>">General</a>
			<a href="<?php echo esc_url('?page=pike_firewall&tab=apache_log_analyze') ?>" class="nav-tab <?php echo $active_tab == 'apache_log_analyze' ? 'nav-tab-active' : ''; ?>">Apache Logs Analyze</a>
			<a href="<?php echo esc_url('?page=pike_firewall&tab=filesystem_scan') ?>" class="nav-tab <?php echo $active_tab == 'filesystem_scan' ? 'nav-tab-active' : ''; ?>">Filesystem Scanner</a>
			<a href="<?php echo esc_url('?page=pike_firewall&tab=filesystem_logs') ?>" class="nav-tab <?php echo $active_tab == 'filesystem_logs' ? 'nav-tab-active' : ''; ?>">Filesystem Logs</a>
			<a href="<?php echo esc_url('?page=pike_firewall&tab=login_attempts') ?>" class="nav-tab <?php echo $active_tab == 'login_attempts' ? 'nav-tab-active' : ''; ?>">User Login Logs</a>
			<a href="<?php echo esc_url('?page=pike_firewall&tab=logs') ?>" class="nav-tab <?php echo $active_tab == 'logs' ? 'nav-tab-active' : ''; ?>">Logs</a>
			<a href="<?php echo esc_url('?page=pike_firewall&tab=crawlers') ?>" class="nav-tab <?php echo $active_tab == 'crawlers' ? 'nav-tab-active' : ''; ?>">Crawler Logs</a>
		</h2>
<?php 
		if ( $active_tab == 'main' ) { 
			
			require_once PIKEFIREWALL_DIR.'partials/pike-firewall-settings-general.php';
			
		} elseif ( $active_tab == 'logs' || $active_tab == 'crawlers' ) { 
			
			$table_key = ( $active_tab == 'logs' ) ? 'log' : 'log_crawlers';
			$table_logs->set_db_table_name($pike_tables[$table_key]);
			$table_logs->prepare_items();
			
			echo '<form method="post" action=""><br/>';
			echo '<input type="hidden" name="page" value="pike_firewall" />';
			echo '<input type="hidden" name="tab" value="'.$active_tab.'" />';
			$table_logs->search_box('search', 'search-id');
			$table_logs->display();
			wp_nonce_field('form_submit', 'pike_nonce');
			echo '</form>';
				
		} elseif ( $active_tab == 'apache_log_analyze' ) {
				
			$result = array();
			$content = "";
			if ( isset($_POST['pike-firewall-apache-log-analyze']) ) {
				if ( !function_exists('wp_handle_upload') ) {
					require_once ABSPATH.'wp-admin/includes/file.php';
				}
				
				$upload_file = $_FILES['pike-firewall-apache-logfile'];
				$upload_overrides = array('test_form' => false);
				
				add_filter('upload_dir', 'pike_get_upload_dir');
				add_filter('upload_mimes', 'pike_change_mimes');
					
				$dir = wp_upload_dir();
				if ( isset($dir['path']) && !file_exists($dir['path'].'/index.php') ) {
					if ( ($fp = @fopen($dir['path'].'/index.php', 'w')) !== false ) {
						$html = "<?php
//grrrrrrrrr";
						@fwrite($fp, $html);
						@fclose($fp);
					}
				}
					
				$move_file = wp_handle_upload($upload_file, $upload_overrides);
				remove_filter('upload_dir', 'pike_get_upload_dir');
				remove_filter('upload_mimes', 'pike_change_mimes');
				
				if ( $move_file && !isset($move_file['error']) ) {
					$result = pike_parse_log_file($move_file['file']);
					if ( is_array($result) && sizeof($result) > 0 ) {
						foreach ( $result as $res ) {
							if ( is_array($res) && sizeof($res) > 0 ) {
								$content .= $res['type'].": ".$res['line']."\n";
							}
						}
					}
				} else {
					pike_error_notice($move_file['error'], 'notice-error');
				}
			}
				
			require_once PIKEFIREWALL_DIR.'partials/pike-firewall-settings-apache-analyze.php';
			
		} elseif ( $active_tab == 'filesystem_scan' ) {
				
			require_once PIKEFIREWALL_DIR.'partials/pike-firewall-settings-filesystem-scan.php';
			
		} elseif ( $active_tab == 'filesystem_logs' ) {
				
			$table_logs->set_db_table_name($pike_tables['filesystem_scan']);
			$table_logs->prepare_items();
				
			echo '<form method="post" action=""><br/>';
			echo '<input type="hidden" name="page" value="pike_firewall" />';
			echo '<input type="hidden" name="tab" value="'.$active_tab.'" />';
			echo '<label><strong>Scan Results:</strong></label>';
			$table_logs->search_box('search', 'search-id');
			$table_logs->display();
			wp_nonce_field('form_submit', 'pike_nonce');
			echo '</form>';
				
			$plugins = get_plugins();
			$active_plugins = get_option('active_plugins');
					
			$themes = wp_get_themes();
			$active_theme = wp_get_theme();
				
			require_once PIKEFIREWALL_DIR.'partials/pike-firewall-settings-filesystem.php';
		
		} elseif ( $active_tab == 'login_attempts' ) {
				
			$table_logs->set_db_table_name($wpdb->prefix."pike_firewall_login");
			$table_logs->prepare_items();
				
			echo '<form method="post" action=""><br/>';
			echo '<input type="hidden" name="page" value="pike_firewall" />';
			echo '<input type="hidden" name="tab" value="'.$active_tab.'" />';
			$table_logs->search_box('search', 'search-id');
			$table_logs->display();
			wp_nonce_field('form_submit', 'pike_nonce');
			echo '</form>';
		} ?>
	</div>
<?php 
}

/** 
 * Load admin js/css files used in the plugin
 * 
 * @param string $page The name of the current page
 * 
 * @return void
 */
function pike_admin_scripts_init($page) {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	wp_enqueue_script('jquery');
	if ( !isset($pike_options['cron_check']) ) {
		wp_register_script('pike-firewall-ajax', plugins_url('js/pike-firewall-ajax.js', __FILE__), array('jquery'));
		wp_localize_script('pike-firewall-ajax', 'pikefirewallAJAX', array('ajaxurl' => admin_url('admin-ajax.php')));
		wp_enqueue_script('pike-firewall-ajax');
	}
	
	if( 'toplevel_page_pike_firewall' != $page ) {
		return;
	}
	
	wp_register_script('pikefirewall-script-ajax-filescan', plugins_url('js/pike-firewall-ajax-filescan.js', __FILE__), array('jquery'));
	wp_localize_script('pikefirewall-script-ajax-filescan', 'pikefirewallAJAXScan', array('ajaxurl' => admin_url('admin-ajax.php')));
	wp_enqueue_script('pikefirewall-script-ajax-filescan');
	
	wp_register_script('pikefirewall-script-ajax-cron-reset', plugins_url('js/pike-firewall-ajax-cron-reset.js', __FILE__), array('jquery'));
	wp_localize_script('pikefirewall-script-ajax-cron-reset', 'pikefirewallAJAXCronReset', array('ajaxurl' => admin_url('admin-ajax.php')));
	wp_enqueue_script('pikefirewall-script-ajax-cron-reset');
}

/** 
 * Load frontend js/css files used in the plugin
 * 
 * @return void
 */
function pike_frontend_scripts_init() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	wp_enqueue_script('jquery');
	if ( !isset($pike_options['cron_check']) ) {
		wp_register_script('pike-firewall-ajax', plugins_url('js/pike-firewall-ajax.js', __FILE__), array('jquery'));
		wp_localize_script('pike-firewall-ajax', 'pikefirewallAJAX', array('ajaxurl' => admin_url('admin-ajax.php')));
		wp_enqueue_script('pike-firewall-ajax');
	}
}

/**
 * AJAX update plugin database
 * 
 * @return void
 */ 
function pike_ajax_scan() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['cron_check']) ) {
		if ( !isset($pike_options['update_progress']) || $pike_options['update_progress'] === 'no' ) {
			// Update in action, deny further update requests from AJAX
			$pike_options['update_progress'] = 'yes';
			update_option('pike_firewall', $pike_options);
			
			pike_update_data();
			
			$pike_options['update_progress'] = 'no';
			update_option('pike_firewall', $pike_options);
			wp_die();	//this is required to terminate immediately and return a proper response
		}
	}
}

/**
 * AJAX filesystem scan
 * 
 * @return void
 */ 
function pike_ajax_filescan() {
	if ( !wp_verify_nonce($_REQUEST['nonce'], 'pike_nonce')) {
		wp_die( __('CSRF detected!') );
	}
	
	pike_file_scan();
	wp_die();
}

/**
 * AJAX filesystem scan cron reset
 * 
 * @return void
 */ 
function pike_ajax_cron_reset() {
	if ( !wp_verify_nonce($_REQUEST['nonce'], 'pike_nonce')) {
		wp_die( __('CSRF detected!') );
	}
	
	if ( wp_get_schedule('fs_update_event') !== false ) {
		wp_clear_scheduled_hook('fs_update_event');
		_e('Cron job removed');
	}
	wp_die();
}

/**
 * Plugin update functionality
 * 
 * @return void
 */ 
function pike_update_plugin() {
	if ( !function_exists('get_plugins') ) {
		require_once ABSPATH.'wp-admin/includes/plugin.php';
	}

	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['version']) || PIKEFIREWALL_VERSION != $pike_options['version'] ) {
		pike_merge_db_singleip_crawlerip();
 		$pike_options['version'] = PIKEFIREWALL_VERSION;
		update_option('pike_firewall', $pike_options);
	}
}

/**
 * Cron job setup
 * 
 * @return void
 */ 
function pike_cron_scan() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['cron_check']) ) {
		if ( wp_get_schedule('hourly_update_event') === false ) {
			wp_schedule_event(time(), 'hourly', 'hourly_update_event');
		}
	} else {
		if ( wp_get_schedule('hourly_update_event') !== false ) {
			wp_clear_scheduled_hook('hourly_update_event');
		}
	}
	
	if ( isset($pike_options['file_scan']['cron']) ) {
		if ( wp_get_schedule('fs_update_event') === false ) {
			$time = ( isset($pike_options['file_scan']['time']) && strtotime($pike_options['file_scan']['time']) !== false ) ? strtotime($pike_options['file_scan']['time']) : time();
			wp_schedule_event($time, 'custom_time', 'fs_update_event');
		}
	} else {
		if ( wp_get_schedule('fs_update_event') !== false ) {
			wp_clear_scheduled_hook('fs_update_event');
		}
	}
}


/**
 * Add custom cron time in the scheduler
 * 
 * @param array $schedules
 * 
 * @return array The array with custom cron job time defined
 */ 
function pike_cron_add_time($schedules) {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);

	$interval = ( isset($pike_options['file_scan']['interval']) && intval($pike_options['file_scan']['interval']) > 0 ) ? $pike_options['file_scan']['interval'] : 1;
	$interval_unit = ( isset($pike_options['file_scan']['interval_unit']) && !empty($pike_options['file_scan']['interval_unit']) ) ? $pike_options['file_scan']['interval_unit'] : 'days';
	$mult = 1;

	switch ( $interval_unit ) {
		case 'min': 
			$mult = 60;
		break;
		
		case 'hours':
			$mult = 60*60;
		break;
		
		case 'days':
			$mult = 24*60*60;
	}
	
	$schedules['custom_time'] = array(
		'interval' => $interval * $mult,
		'display' => __('File system scan - scheduled job')
	);
	
	return $schedules;
}

/** 
 * Cron update plugin database
 * 
 * @return void
 */
function pike_cron_job() {
	pike_update_data(TRUE);
	wp_die();
}

/** 
 * Cron filesystem scan
 * 
 * @return void
 */
function pike_cron_job_filescan() {
	pike_file_scan();
	wp_die();
}

/**
 * CSRF attack prevention with plugin generated nonce
 * 
 * @return void
 */ 
function pike_csrf_protect() {
	if ( isset($_POST['pike-firewall-submit']) || 
		 isset($_POST['pike-firewall-delete']) || 
		 isset($_POST['pike-firewall-csv']) || 
		 isset($_POST['pike-firewall-csv-crawlers']) || 
		 isset($_POST['pike-firewall-apache-log-analyze']) || 
		 isset($_POST['pike-firewall-analyze-csv']) ||
		 isset($_POST['pike-firewall-csv-login'])
	) {
		if ( !isset($_POST['pike_nonce']) || !wp_verify_nonce(esc_attr($_POST['pike_nonce']), 'form_submit') ) {
			wp_die( __('CSRF detected!'), '', 403 );
		}
	}
	
	if ( isset($_POST['page']) && $_POST['page'] == 'pike_firewall' ) {
		if ( (isset($_POST['action']) && $_POST['action'] == 'bulk-delete') || 
			 (isset($_POST['action1']) && $_POST['action1'] == 'bulk-delete') || 
			  isset($_REQUEST['s']) && !empty($_REQUEST['s']) 
		) {
			if ( !isset($_POST['pike_nonce']) || !wp_verify_nonce(esc_attr($_POST['pike_nonce']), 'form_submit') ) {
				wp_die( __('CSRF detected!'), '', 403 );
			}
		}
	}	
}

/**
 * Create csv files from the logs
 * 
 * @return void
 */ 
function pike_convert_to_csv() {
	if ( isset($_POST['pike-firewall-csv']) || isset($_POST['pike-firewall-csv-crawlers']) ) {	
		
		$table_key = ( isset($_POST['pike-firewall-csv']) ) ? 'log' : 'log_crawlers';
		$csv_filename = ( isset($_POST['pike-firewall-csv']) ) ? 'pike_firewall_logs_'.date('Y-m-d', time()).'.csv' : 'pike_firewall_crawler_logs_'.date('Y-m-d', time()).'.csv';
		$logs = pike_get_logs($table_key);
		
		// Export the data and prompt a csv file for download
		@header('Content-Type: text/csv; charset=utf-8');
		@header('Content-Disposition: attachment; filename='.$csv_filename);

		$fp = @fopen('php://output', 'w+');
		@fputcsv($fp, array('IP', 'URL', 'Type', 'Time'));
		if ( $logs !== NULL && is_array($logs) && sizeof($logs) > 0 ) {
			foreach ( $logs as $log  ) {
				@fputcsv($fp, array($log['ip'], urldecode($log['landing_page']), $log['type'], $log['systime']));
			}
		}
		@fclose($fp);
		exit;
	
	} elseif ( isset($_POST['pike-firewall-analyze-csv']) ) {
		
		$csv_filename = 'pike_firewall_logs_analyzed_'.date('Y-m-d', time()).'.csv';
		$content = trim($_POST['pike-firewall-logs-print']);
		$result = ( strlen($content) > 0 ) ? explode("\r\n", $content) : array();
								
		@header('Content-Type: text/csv; charset=utf-8');
		@header('Content-Disposition: attachment; filename='.$csv_filename);

		$fp = @fopen('php://output', 'w+');
		if ( is_array($result) && sizeof($result) > 0 ) {
			foreach ( $result as $res ) {
				$tmp = explode(': ', $res);
				@fputcsv($fp, array($tmp[0], stripslashes($tmp[1])), ',', ' ');
			}
		}
		@fclose($fp);
		exit;
		
	} elseif ( isset($_POST['pike-firewall-csv-login']) ) {
		
		$csv_filename = 'pike_firewall_login_logs_'.date('Y-m-d', time()).'.csv';
		$logs = pike_get_logs('login');
		
		@header('Content-Type: text/csv; charset=utf-8');
		@header('Content-Disposition: attachment; filename='.$csv_filename);

		$fp = @fopen('php://output', 'w+');
		@fputcsv($fp, array('User', 'IP', 'User-Agent', 'Type', 'Success', 'Time'));
		if ( $logs !== NULL && is_array($logs) && sizeof($logs) > 0 ) {
			foreach ( $logs as $log  ) {
				@fputcsv($fp, array($log['username'], $log['user_address'], $log['user_agent'], $log['type'], $log['success'], $log['login_time']));
			}
		}
		@fclose($fp);
		exit;
		
	}
}

/**
 * Stealth mode logging => every single bad visit on site is logged in database
 * 
 * @return void
 */ 
function pike_stealth_mode() {
	global $pike_settings, $pike_ip, $pike_agent;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['stealth_mode']) ) {
		if ( ($match_data = pike_match_ip()) !== false ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		} else {
			$wphost = parse_url(site_url(), PHP_URL_HOST);
			if ( ($vendor = pike_get_vendor($pike_agent)) !== false ) {
				if ( pike_check_whitelist(ip2long($pike_ip)) === false ) {
					if ( !($vendor == 'facebook' || pike_check_FCrDNS($vendor, $pike_ip)) ) {
						pike_parse_log($pike_ip, 'Fake Crawler');
					}
				}
			} elseif ( !pike_check_post_ua() ) {
				pike_parse_log($pike_ip, 'Blank User Agent');
			} elseif ( !pike_check_post_ua_cmd() ) {
				pike_parse_log($pike_ip, 'cmd Browser / Software library');
			} elseif ( !pike_check_proxy_by_headers() ) {
				pike_parse_log($pike_ip, 'Proxy Headers');
			} elseif ( !pike_check_post_referer($wphost) ) {
				pike_parse_log($pike_ip, 'Foreign Origin');
			} elseif ( !pike_check_user_enum() ) {
				pike_parse_log($pike_ip, 'User Enumeration');
			} 
		}
	}
}

/**
 * Show Captcha
 * 
 * @return void
 */ 
function pike_show_captcha() {		
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
		
	if ( isset($pike_options['captcha_check']) ) {
		if ( pike_match_ip() !== false ) {
			$captcha_valid = ( isset($_COOKIE['pike_captcha_valid']) ) ? $_COOKIE['pike_captcha_valid'] : false;
			if ( !$captcha_valid ) {	
				status_header(403);
				require_once PIKEFIREWALL_DIR.'partials/pike-firewall-captcha.php';
				exit;
			}
		}
	}
}

/**
 * Block fake crawlers / Verify crawlers
 * 
 * @return void
 */ 
function pike_block_crawlers() {
	global $pike_settings, $pike_ip, $pike_agent;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['crawler_check']) ) {
		// If IP address is already in fake crawler table, block it immediately
		if ( pike_get_table_data('crawl_fake_ip', ip2long($pike_ip)) !== NULL ) {
			if ( isset($pike_options['send_email'][0]) ) {
				$notification_title = "Fake Crawler";
				pike_notifications($notification_title);
			}
			
			if ( !isset($pike_options['stealth_mode']) ) {
				pike_parse_log($pike_ip, 'Fake Crawler');
			}
			
			$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $pike_ip) : __('Your IP address has been blocked.');
			wp_die( __($block_msg), '', 503 );
		}
		
		if ( ($user_agent = pike_get_vendor($pike_agent)) !== false ) {
			if ( pike_get_table_data('single_ip', ip2long($pike_ip)) !== NULL ) {
				if ( isset($pike_options['send_email'][0]) ) {
					$notification_title = "Fake Crawler";
					pike_notifications($notification_title);
				}
			
				if ( !isset($pike_options['stealth_mode']) ) {
					pike_parse_log($pike_ip, 'Fake Crawler');
				}
				
				$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $pike_ip) : __('Your IP address has been blocked.');
				wp_die( __($block_msg), '', 503 );
			} else {
				pike_check_crawler($pike_ip, $user_agent);
				if ( pike_get_table_data('range_ip', ip2long($pike_ip)) !== NULL ) {
					if ( pike_check_whitelist(ip2long($pike_ip)) === false ) {
						if ( isset($pike_options['send_email'][0]) ) {
							$notification_title = "Fake Crawler";
							pike_notifications($notification_title);
						}
						
						$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $pike_ip) : __('Your IP address has been blocked.');
						wp_die( __($block_msg), '', 503 );
					}
				} else {
					if ( pike_get_table_data('crawl_fake_ip', ip2long($pike_ip)) !== NULL ) {
						if ( isset($pike_options['send_email'][0]) ) {
							$notification_title = "Fake Crawler";
							pike_notifications($notification_title);
						}
						
						$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $pike_ip) : __('Your IP address has been blocked.');
						wp_die( __($block_msg), '', 503 );
					}
				}
			}
		}
	}	
}

/**
 * Verify crawler
 * 
 * @param string $ip_address
 * @param string $user_agent
 * 
 * @return void
 */ 
function pike_check_crawler($ip_address, $user_agent) {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( pike_check_whitelist(ip2long($ip_address)) === false ) {
		if ( $user_agent == 'facebook' || pike_check_FCrDNS($user_agent, $ip_address) ) {
			pike_insert_ip('crawl_ip', ip2long($ip_address), $user_agent);
			if ( isset($pike_options['crawler_analyze'][$user_agent]) ) {
				pike_parse_log($ip_address, $user_agent, TRUE);
			}
		} else {
			pike_insert_ip('crawl_fake_ip', ip2long($ip_address), $user_agent);
			pike_insert_ip('single_ip', ip2long($ip_address));
			if ( !isset($pike_options['stealth_mode']) ) {
				pike_parse_log($ip_address, 'Fake Crawler');
			}
		}
	} else {
		if ( isset($pike_options['crawler_analyze'][$user_agent]) ) {
			pike_parse_log($ip_address, $user_agent, TRUE);
		}
	}
}

/**
 * Block public site visits
 * 
 * @return void
 */ 
function pike_read_public_content() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['check']['visit']) && !is_admin() && ($match_data = pike_match_ip()) !== false ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "Public content read";
			pike_notifications($notification_title);
		} */
						
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
		
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to read any public content from this site.');
		wp_die( __($block_msg), '', 503 );
	}
}

/**
 * Block comments
 * 
 * @return void
 */ 
function pike_send_comment() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['check']['comment']) && !empty($_POST['comment']) && ($match_data = pike_match_ip()) !== false ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "Posting comment";
			pike_notifications($notification_title);
		} */
		
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
		
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to comment on this site.');
		wp_die( __($block_msg), '', 503 );
	}		
}

/**
 * Block user registration
 * 
 * @return void
 */ 
function pike_user_registration() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['check']['registration']) && ($match_data = pike_match_ip()) !== false ) {
		if ( isset($pike_options['send_email'][2]) ) {
			$notification_title = "User registration";
			pike_notifications($notification_title);
		}
		
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
			
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to register on this site.');
		wp_die( __($block_msg), '', 503 );
	}
}

/**
 * Block subscriptions
 * 
 * @return void
 */ 
function pike_user_subscription() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$url_parts = explode('/', $_SERVER['REQUEST_URI']);
	if ( !isset($pike_options['check']['subscription']) && (in_array('feed', array_keys($_REQUEST)) || in_array('feed', $url_parts)) && ($match_data = pike_match_ip()) !== false ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "User subscription";
			pike_notifications($notification_title);
		} */
		
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
	
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to subscribe for this site.');
		wp_die( __($block_msg), '', 503 );
	}		
}

/**
 * Block Admin Dashboard access
 * 
 * @return void
 */ 
function pike_admin_dashboard_access() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['check']['administration']) && ($match_data = pike_match_ip()) !== false ) {
		if ( isset($pike_options['send_email'][1]) ) {
			$notification_title = "Admin Dashboard access";
			pike_notifications($notification_title);
		}
		
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}

		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to access the Admin Dashboard.');
		wp_die( __($block_msg), '', 503 );
	}		
}

/**
 * Block POST requests
 * 
 * @return void
 */ 
function pike_deny_post_requests() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( !isset($pike_options['check']['request']) && $_SERVER['REQUEST_METHOD'] == 'POST' && ($match_data = pike_match_ip()) !== false ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "POST request";
			pike_notifications($notification_title);
		} */
		
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
	
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to make POST requests on this site.');
		wp_die( __($block_msg), '', 503 );
	}		
}

/**
 * Block all requests that contain predefined parameters
 * 
 * @return void
 */ 
function pike_deny_all_requests() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$all_requests = explode(',', $pike_options['deny']);
	$check = false;
	foreach ( $all_requests as $request ) {
		if ( (in_array(trim($request), array_keys($_POST)) || in_array(trim($request), array_keys($_GET)) || in_array(trim($request), array_keys($_REQUEST))) && ($match_data = pike_match_ip()) != false ){
			$check = true;
			break;
		}
	}
	
	if ( $check ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "HTTP request";
			pike_notifications($notification_title);
		} */
		
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
		
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('You do NOT have sufficient permissions to make any requests on this site.');
		wp_die( __($block_msg), '', 503 );
	}		
}

/**
 * Block foreign User-Agent requests
 * 
 * @return void
 */ 
function pike_foreign_request() {
	global $pike_settings, $pike_ip;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$wphost = parse_url(site_url(), PHP_URL_HOST);
	if ( isset($pike_options['intrusion']['foreign_origin']) && ($pike_ip != $_SERVER['SERVER_ADDR']) && !pike_check_post_referer($wphost) ) {
		if ( isset($pike_options['send_email'][3]) ) {
			$notification_title = "Foreign Origin User-Agent";
			pike_notifications($notification_title);
		}
		
		$match_data = array('ip' => $pike_ip, 'type' => 'Foreign Origin');
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
		
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('Blocked request: User-Agent from foreign origin.');
		wp_die( __($block_msg), '', 503 );
	}
}	

/**
 * Block blank User-Agent and/or User-Agent set by cmd Browser or Software library
 * 
 * @return void
 */ 
function pike_user_agent() {
	global $pike_settings, $pike_ip;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['intrusion']['blank_useragent']) && ($pike_ip != $_SERVER['SERVER_ADDR']) && !pike_check_post_ua() ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "Blank User-Agent";
			pike_notifications($notification_title);
		} */
		
		$match_data = array('ip' => $pike_ip, 'type' => 'Blank User Agent');
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}

		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('Blocked request: blank User-Agent.');
		wp_die( __($block_msg), '', 503 );
	}
	
	if ( isset($pike_options['intrusion']['cmd_useragent']) && ($pike_ip != $_SERVER['SERVER_ADDR']) && !pike_check_post_ua_cmd() ) {
		if ( isset($pike_options['send_email'][4]) ) {
			$notification_title = "cmd Browser / Software library";
			pike_notifications($notification_title);
		}
		
		$match_data = array('ip' => $pike_ip, 'type' => 'cmd Browser / Software library');
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
		
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('Blocked request: cmd Browser or Software library.');
		wp_die( __($block_msg), '', 503 );
	}
} 

/**
 * Block WP user enumeration
 * 
 * @return void
 */ 
function pike_user_enumeration() {
	global $pike_settings, $pike_ip;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['intrusion']['user_enumeration']) && !pike_check_user_enum() ) {
		if ( isset($pike_options['send_email'][5]) ) {
			$notification_title = "User Enumeration";
			pike_notifications($notification_title);
		}
		
		$match_data = array('ip' => $pike_ip, 'type' => 'User Enumeration');
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
	
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('Wordpress User Enumeration detected.');
		wp_die( __($block_msg), '', 503 );
	}
}

/**
 * Block Proxy headers
 * 
 * @return void
 */ 
function pike_proxy_headers() {
	global $pike_settings, $pike_ip;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['intrusion']['proxy_headers']) && ($pike_ip != $_SERVER['SERVER_ADDR']) && !pike_check_proxy_by_headers() ) {
		/*
		if ( isset($pike_options['send_email'][0]) ) {
			$notification_title = "Proxy Headers";
			pike_notifications($notification_title);
		} */
		
		$match_data = array('ip' => $pike_ip, 'type' => 'Proxy Headers');
		if ( !isset($pike_options['stealth_mode']) ) {
			pike_parse_log($match_data['ip'], $match_data['type']);
		}
	
		$block_msg = ( isset($pike_options['custom_msg']['enable']) ) ? pike_shortcode_replace($pike_options['custom_msg']['text'], $match_data['ip']) : __('Proxy Headers detected.');
		wp_die( __($block_msg), '', 503 );
	}
}

/**
 * Register the plugin widget
 * 
 * @return void
 */ 
function pike_register_widget() {
	wp_register_sidebar_widget(
		'pike-firewall-widget',		//unique widget id
		'Pike Firewall Widget',		//widget name
		'pike_widget_display',		//callback function
		array(                     	//options
			'description' => __('Pike Firewall Widget', 'text_domain')
		)
	);
}	

/**
 * Display widget functionality
 * 
 * @param array $args The arguments for widget display
 * 
 * @return void
 */ 
function pike_widget_display($args) {
	echo $args['before_widget'];	
	if ( ($match_data = pike_match_ip()) != false ) {
		echo "<div class='pike-block-screen' style='display:table; margin:0 auto;'>";
		echo "<img src='data:image/jpeg;base64,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' width='60px' /><br/>";
		echo "<strong>".esc_html($match_data['ip'])."</strong>";
		echo "</div>";
	}
	echo $args['after_widget'];
}

/**
 * Create plugin tables in database
 * 
 * @param string $key The key for the tables array
 * @param string $table the name of the table
 * 
 * @return void
 */ 
function pike_create_table($key="", $table) {
	switch ( $key ) {
		case 'single_ip':
			$sql = "CREATE TABLE $table (ip INT(11) UNSIGNED NOT NULL, PRIMARY KEY (ip))";
		break;
			
		case 'range_ip':
			$sql = "CREATE TABLE $table (min INT(11) UNSIGNED NOT NULL, max INT(11) UNSIGNED NOT NULL, KEY (min), KEY (max))";
		break;
		
		case 'crawl_ip':
		case 'crawl_fake_ip':
			$sql = "CREATE TABLE $table (id INT(11) AUTO_INCREMENT NOT NULL, intip INT(11) UNSIGNED NOT NULL, provider INT(11) NOT NULL, timecreated TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, PRIMARY KEY (id), UNIQUE(intip))";
		break;
		
		case 'crawl_range_ip':
			$sql = "CREATE TABLE $table (id INT(11) AUTO_INCREMENT NOT NULL, minip INT(11) UNSIGNED NOT NULL, maxip INT(11) UNSIGNED NOT NULL, provider INT(11) NOT NULL, PRIMARY KEY (id))";
		break;
		
		case 'log':
		case 'log_crawlers':
			$sql = "CREATE TABLE $table
						(id INT(10) NOT NULL AUTO_INCREMENT,
						 ip VARCHAR(25) NOT NULL,
						 landing_page TEXT NOT NULL,
						 type VARCHAR(255) NOT NULL,
						 systime TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL ,
						 PRIMARY KEY (id))";
		break;
		
		case 'filesystem_scan':
			$sql = "CREATE TABLE $table (id INT(11) NOT NULL AUTO_INCREMENT, files LONGTEXT NOT NULL, time_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (id))";
		break;
		
		case 'login':
			$sql = "CREATE TABLE $table 
						(id INT(11) NOT NULL AUTO_INCREMENT, 
						 username VARCHAR(25) NOT NULL, 
						 user_address VARCHAR(25) NOT NULL, 	
						 user_agent TEXT NOT NULL, type VARCHAR(255) NOT NULL, 
						 success TINYINT(1) NOT NULL, 
						 login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, 
						 PRIMARY KEY (id))";
		break;
		
		default: 
			$sql = "";
	}
	
	require_once ABSPATH.'wp-admin/includes/upgrade.php';
 	dbDelta($sql);
}

/**
 * Drop plugin database tables
 * 
 * @param string $table The name of the table
 * 
 * @return void
 */ 
function pike_drop_table($table) {
	global $wpdb;
	
	$sql = "DROP TABLE IF EXISTS $table";
	$wpdb->query($sql);
	delete_option('pike_firewall');
}

/**
 * Truncate plugin tables
 * 
 * @param string The name of the table
 * 
 * @return boolean
 */ 
function pike_empty_table($table) {
	global $wpdb;
	
	$sql = "TRUNCATE $table";
	if ( $wpdb->query($sql) ) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Plugin install
 * 
 * @return void
 */ 
function pike_install() {	
	$pike_tables = pike_all_tables();
	foreach ( $pike_tables as $key => $table ) {
		pike_create_table($key, $table);
	}
}

/**
 * Fill database tables with data
 * 
 * @return void
 */ 
function pike_install_data() {
	$pike_tables = pike_all_tables();
	$pike_settings = pike_default_settings();
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$fallback_check = true;
	$range_check = true;
	
	$crawler_range_ip = pike_get_crawler_ip($pike_options['default_crawlers']['url']);
	if ( is_array($crawler_range_ip) && sizeof($crawler_range_ip) > 0 ) {
		pike_crawler_ip_fill_table($crawler_range_ip, $pike_tables['crawl_range_ip']);
	}
	
	$range_ip = pike_get_ip($pike_options['default_range']['url'], false, $range_check);
	$range_ip_long = pike_ip_to_long($range_ip, $range_check);
	if ( is_array($range_ip_long) && sizeof($range_ip_long) > 0 ) {
		pike_ip_fill_table($range_ip_long, $pike_tables['range_ip'], $range_check);
	}
	
	$tor_ip = pike_get_ip($pike_options['default_tor']['url'], $fallback_check);
	$tor_ip_long = pike_ip_to_long($tor_ip);
	
	$proxy_ip = pike_get_ip($pike_options['default_proxy']['url']);
	$proxy_ip_long = pike_ip_to_long($proxy_ip);
		
	if ( is_array($tor_ip_long) && sizeof($tor_ip_long) > 0 && is_array($proxy_ip_long) && sizeof($proxy_ip_long) > 0 ) {
		$merged_ip = pike_append_arrays($tor_ip_long, $proxy_ip_long);
		if ( $merged_ip !== 0 ) {
			pike_ip_fill_table($merged_ip, $pike_tables['single_ip']);
		}
	} else {
		if ( is_array($tor_ip_long) && sizeof($tor_ip_long) > 0 ) {
			pike_ip_fill_table($tor_ip_long, $pike_tables['single_ip']);
		} elseif ( is_array($proxy_ip_long) && sizeof($proxy_ip_long) > 0 ) {
			pike_ip_fill_table($proxy_ip_long, $pike_tables['single_ip']);
		}
	}
}	

/**
 * Update plugin data using pike services
 * 
 * @param boolean $cron Is it a cron job or not
 * 
 * @return void
 */ 
function pike_update_data($cron=false) {
	global $pike_settings, $pike_tables;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$update_time = 1800;
	$fallback_check = true;
	$range_check = true;
	$update = false;
	$crawl_update = false;
	
	$tor_ip_long = array();
	$proxy_ip_long = array();

	$time_point = time();
	$interval = $time_point - $pike_options['services_update_time'];
	$interval_crawlers = $time_point - $pike_options['crawlers_update_time'];

	if ( isset($pike_options['default_crawlers']['enable']) && $pike_options['default_crawlers']['url'] == $pike_settings['default_crawlers']['url'] && (isset($pike_options['cron_check']) || $interval_crawlers >= strtotime('30 days')) ) {
		if ( pike_empty_table($pike_tables['crawl_range_ip']) ) {
			$crawler_range_ip = pike_get_crawler_ip($pike_options['default_crawlers']['url']);
			if ( is_array($crawler_range_ip) && sizeof($crawler_range_ip) > 0 ) {
				pike_crawler_ip_fill_table($crawler_range_ip, $pike_tables['crawl_range_ip']);
				$crawl_update = true;
			}
		}
	}

	if ( isset($pike_options['default_range']['enable']) && $pike_options['default_range']['url'] == $pike_settings['default_range']['url'] && (isset($pike_options['cron_check']) || $interval >= $update_time) ) {
		if ( pike_empty_table($pike_tables['range_ip']) ) {
			$range_ip = pike_get_ip($pike_options['default_range']['url'], false, $range_check);
			$range_ip_long = pike_ip_to_long($range_ip, $range_check);
			if ( is_array($range_ip_long) && sizeof($range_ip_long) > 0 ) {
				pike_ip_fill_table($range_ip_long, $pike_tables['range_ip'], $range_check);
				$update = true;
			}
		}
	}

	if ( isset($pike_options['default_proxy']['enable']) && $pike_options['default_proxy']['url'] == $pike_settings['default_proxy']['url'] && (isset($pike_options['cron_check']) || $interval >= $update_time) ) {
		$proxy_ip = pike_get_ip($pike_options['default_proxy']['url']);
		$proxy_ip_long = pike_ip_to_long($proxy_ip);
	}

	if ( isset($pike_options['default_tor']['enable']) && (($pike_options['default_tor']['url'] == $pike_settings['default_tor']['url'] && (isset($pike_options['cron_check']) || $interval >= $update_time)) || (preg_match("/^http(s)?:\/\/(w{3}\.)?pike.hqpeak.com(\/.+)+\?id=[0-9a-zA-Z]{40}&format=json/", $pike_options['default_tor']['url']) && (isset($pike_options['cron_check']) || $interval >= 400))) ) {
		$tor_ip = pike_get_ip($pike_options['default_tor']['url'], $fallback_check);
		$tor_ip_long = pike_ip_to_long($tor_ip);
	}
			
	if ( is_array($tor_ip_long) && sizeof($tor_ip_long) > 0 && is_array($proxy_ip_long) && sizeof($proxy_ip_long) > 0 ) {
		if ( pike_empty_table($pike_tables['single_ip']) ) {
			$merged_ip = pike_append_arrays($tor_ip_long, $proxy_ip_long);
			if ( $merged_ip !== 0 ) {
				pike_ip_fill_table($merged_ip, $pike_tables['single_ip']);
				$update = true;
			}
		}
	} else {
		if ( is_array($tor_ip_long) && sizeof($tor_ip_long) > 0 ) {
			if ( pike_empty_table($pike_tables['single_ip']) ) {
				pike_ip_fill_table($tor_ip_long, $pike_tables['single_ip']);
				$update = true;
			}
		} elseif ( is_array($proxy_ip_long) && sizeof($proxy_ip_long) > 0 ) {
			if ( pike_empty_table($pike_tables['single_ip']) ) {
				pike_ip_fill_table($proxy_ip_long, $pike_tables['single_ip']);
				$update = true;
			}
		}
	}
	
	if ( !isset($pike_options['cron_check']) ) {
		if ( $crawl_update ) {
			$pike_options['crawlers_update_time'] = time();
		}
		
		if ( $update ) {
			$pike_options['services_update_time'] = time();
		}
		
		update_option('pike_firewall', $pike_options);
	}
}

/**
 * Plugin uninstall
 * 
 * @return void
 */ 
function pike_uninstall() {
	$pike_tables = pike_all_tables();
	foreach ( $pike_tables as $table ) {
		pike_drop_table($table);
	}
	
	delete_option('pike_firewall');	
	
	if ( wp_get_schedule('hourly_update_event') !== false ) {
		wp_clear_scheduled_hook('hourly_update_event');
	}
	
	if ( wp_get_schedule('fs_update_event') !== false ) {
		wp_clear_scheduled_hook('fs_update_event');
	}
}

/**
 * Match bad IP address
 * 
 * @return array|boolean
 */ 
function pike_match_ip() {
	global $pike_ip;
	
	$ip_long = ip2long($pike_ip);
	if ( $ip_long !== NULL ) {
		if ( (($result = pike_get_table_data('single_ip', $ip_long)) !== NULL) && (($result = pike_get_table_data('crawl_fake_ip', $ip_long)) === NULL) ) {
			return array('ip' => $pike_ip, 'type' => 'Tor/Proxy');
		} elseif ( ($result = pike_get_table_data('range_ip', $ip_long)) !== NULL ) {
			return array('ip' => $pike_ip, 'type' => 'Datacenter');
		}
	}
	
	return FALSE;
}

/**
 * Check the User-Agent against given vendors
 * 
 * @param string @user_agent
 * 
 * @return string|boolean
 */ 
function pike_get_vendor($user_agent="") {
	$crawlers_identification_strings = array(
		'google'	=> array('google'),
		'bing'		=> array('bingbot', 'msnbot', 'bingpreview'),
		'yahoo'		=> array('yahoo! slurp.'),
		'yandex'	=> array('http://yandex.com/bots'),
		'facebook'	=> array('facebookexternalhit', 'facebot')
	);
	
	$ua = strtolower($user_agent);
	foreach ( $crawlers_identification_strings as $vendor => $pattern ) {
		if ( is_array($pattern) && sizeof($pattern) > 0 ) {
			foreach ( $pattern as $pi ) {
				if ( strpos($ua, $pi) !== false ) {
					return $vendor;
				}
			}
		}
	}
	
	return FALSE;
}

/**
 * Retrieve all data from database from a given plugin table
 * 
 * @param string $key The key for the tables array
 * @param int $ip_long Long representation of the IP address
 * 
 * @return void
 */ 
function pike_get_table_data($key="", $ip_long) {
	global $wpdb, $pike_tables;
	
	switch ( $key ) {
		case 'single_ip':
			$sql = $wpdb->prepare("SELECT * FROM $pike_tables[$key] WHERE `ip` = %s", $ip_long);
		break;
				
		case 'range_ip':
			$sql = $wpdb->prepare("SELECT * FROM $pike_tables[$key] WHERE `min` <= %s AND `max` >= %s", $ip_long, $ip_long);
		break;
		
		case 'crawl_ip':
		case 'crawl_fake_ip':
			$sql = $wpdb->prepare("SELECT * FROM $pike_tables[$key] WHERE `intip` = %s", $ip_long);
		break;
		
		case 'crawl_range_ip':
			$sql = $wpdb->prepare("SELECT * FROM $pike_tables[$key] WHERE `minip` <= %s AND `maxip` >= %s", $ip_long, $ip_long);
		break;
		
		default: 
			$sql = "";
	}
	
	return $wpdb->get_row($sql, ARRAY_A);
}

/**
 * Get pike service data
 * 
 * @param string $url Service URL
 * @param boolean $fallback_service Whether to use fallback service or not in case of failure
 * @param boolean $range_check Whether it is a range IP or a single IP
 * 
 * @return array
 */ 
function pike_get_ip($url="", $fallback_check=false, $range_check=false) {
	$result = array();
	$pattern = "/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}/";
	$response = wp_remote_get($url);
	if ( !is_wp_error($response) && is_array($response) && isset($response['body']) && strlen($response['body']) > 0 ) {
		$data = $response['body'];
	} else {
		if ( $fallback_check ) {
			$data = pike_fallback_service();
		} else {
			return array();
		}
	}

	$service_data = json_decode($data, true);
	
	// Never trust the input - sanitize every IP
	if ( is_array($service_data) && ($size = sizeof($service_data)) > 0 ) {
		for ( $i=0; $i<$size; $i++ ) {
			if ( $range_check ) {
				if ( preg_match($pattern, $service_data[$i][0]) && preg_match($pattern, $service_data[$i][1]) ) {
					$result[] = array($service_data[$i][0], $service_data[$i][1]);
				}
			} else {
				if ( preg_match($pattern, $service_data[$i]) ) {
					$result[] = $service_data[$i];
				}
			}
		}
	} else {
		return array();
	}
	
	return $result;
}

/**
 * Pike service fallback
 * 
 * @return object
 */ 
function pike_fallback_service() {	
	$service_data = array();
	$response = wp_remote_get('https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=8.8.8.8&port=');
	if ( !is_wp_error($response) && is_array($response) && isset($response['body']) ) {
		$data = explode("\n", $response['body']);
		foreach ( $data as $part ) {
			if ( !preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $part) ) {
				array_shift($data);
			}
		}
		$service_data = $data;
	}
	return json_encode($service_data);
}

/**
 * Get pike service data for crawlers
 * 
 * @param string $url Service URL
 * 
 * @return array
 */ 
function pike_get_crawler_ip($url="") {
	$result = array();
	$minmax = array();
	$pattern = "/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}/";
	$response = wp_remote_get($url);
	if ( !is_wp_error($response) && is_array($response) && isset($response['body']) && strlen($response['body']) > 0 ) {
		$data = $response['body'];
	} else {
		return array();
	}
	
	$service_data = json_decode($data, true);
	
	if ( is_array($service_data) && ($size = sizeof($service_data)) > 0 ) {
		foreach ( $service_data as $vendor => $ip ) {
			if ( is_array($ip) && ($size = sizeof($ip)) > 0 ) {
				for ( $i=0; $i<$size; $i++ ) {
					if ( preg_match($pattern, $ip[$i][0]) && preg_match($pattern, $ip[$i][1]) ) {
						$minmax[] = array($ip[$i][0], $ip[$i][1]);
					}
				}
				$result[$vendor] = $minmax;
			}
		}
	} else {
		return array();
	}
	
	return $result;
}

/**
 * Convert IP address into long format
 * 
 * @param array $result An array of IP addresses
 * @param boolean $range_check Whether it is a range IP or a single IP
 * 
 * @return array|boolean
 */ 
function pike_ip_to_long($result=array(), $range_check=false) {
	if ( is_array($result) ) {
		$ip2long = array();
		if ($range_check) {
			foreach ( $result as $key => $value ) {		
				$ip2long[$key][0] = ip2long($value[0]);
				$ip2long[$key][1] = ip2long($value[1]);
			}
		} else {
			$result = array_unique($result);
			foreach ( $result as $ip ) {
				$ip2long[] = ip2long($ip);
			}
		}
	} else {
		return FALSE;
	}
	
	return $ip2long;
}

/**
 * Fill in database with data from pike services
 * 
 * @param array $result An array of IP addresses
 * @param string $table The name of the table
 * @param boolean $range_check Whether it is a range IP or a single IP
 * 
 * @return void
 */ 
function pike_ip_fill_table($result=array(), $table, $range_check=false) {
	global $wpdb;
	
	$tmp = $result;
	if ( $range_check ) {
		end($result);
		$counter = key($result);
		$limit = 600;
		$q = $counter/$limit;
	} else {
		$limit = 300;
		$q = sizeof($result)/$limit;
	}
	
	for ( $i=0; $i<=$q; $i++ ) {
		$result = array();
		for( $k=$i*$limit; $k<($i+1)*$limit; $k++ ) {
			if ( isset($tmp[$k])) {
				$result[] = $tmp[$k];
			}
		}
		
		if ( is_array($result) && sizeof($result) > 0 ) {
			if ( $range_check ) {
				$sql = "INSERT INTO $table (`min`, `max`) VALUES ";
				foreach ( $result as $ip ) {
					$sql .= $wpdb->prepare("(%s, %s), ", $ip[0], $ip[1]);
				}
			} else {
				$sql = "INSERT INTO $table (`ip`) VALUES ";
				foreach ( $result as $ip ) {
					$sql .= $wpdb->prepare("(%s), ", $ip);
				}	
			}
			
			$sql = rtrim($sql, ', ');
			$wpdb->query($sql);
		}
	}
}

/**
 * Fill in database with crawler data from  pike services
 * 
 * @param array $result An array of long IP addresses
 * @param string $table The name of the table
 * 
 * @return void
 */ 
function pike_crawler_ip_fill_table($result=array(), $table) {
	global $wpdb;
	
	$vendors = array(
		'google'	=> '1',
		'bing'		=> '2',
		'yahoo'		=> '3',
		'yandex'	=> '4',
		'facebook'	=> '5'
	);
	
	if ( is_array($result) && sizeof($result) > 0 ) {
		$sql = "INSERT INTO $table (`minip`, `maxip`, `provider`) VALUES ";
		foreach ( $result as $vendor => $ip ) {
			for ( $i=0; $i<sizeof($ip); $i++ ) {
				$sql .= $wpdb->prepare("(%s, %s, %s), ", ip2long($ip[$i][0]), ip2long($ip[$i][1]), $vendors[$vendor]);
			}
		}			
		
		$sql = rtrim($sql, ', ');
		$wpdb->query($sql);
	}
}

/**
 * Check crawlers whitelists
 * 
 * @param int $ip_long Long representation of the IP address
 * 
 * @return array|boolean
 */ 
function  pike_check_whitelist($ip_long) {
	global $wpdb, $pike_tables, $pike_vendors;
	
	$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM ".$pike_tables['crawl_ip']." WHERE `intip` = %s", $ip_address), ARRAY_A);
	if ( $row === NULL ) {
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM ".$pike_tables['crawl_range_ip']." WHERE `minip` <= %s AND `maxip` >= %s", $ip_address, $ip_address), ARRAY_A);
		if ( $row === NULL ) {
			return FALSE;
		}
	}
	
	if ( isset($pike_vendors[$row['provider']]) ) {
		return $pike_vndors[$row['provider']];
	} else {
		return FALSE;
	}
}

/**
 * Insert IP address into database
 * 
 * @param string $key The key for the tables array
 * @param int $ip_long Long representation of the IP 
 * @param string $user_agent The user agent
 * 
 * @return boolean
 */ 
function pike_insert_ip($key, $ip_long, $user_agent=NULL) {
	global $wpdb, $pike_tables, $pike_vendors;
	
	switch ( $key ) {
		case 'single_ip':
			$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $pike_tables[$key] WHERE `ip` = %s", $ip_long), ARRAY_A);
			if ( $row === NULL ) {
				$sql = $wpdb->prepare("INSERT INTO $pike_tables[$key] (`ip`) VALUES(%s)", $ip_long);
				$wpdb->query($sql);
				return TRUE;
			} else {
				return FALSE;
			}
		break;
		
		case 'crawl_ip':
		case 'crawl_fake_ip':
			$ik = 0;
			foreach ( $pike_vendors as $k => $v ) {
				if ( $v == $user_agent ) {
					$ik = $k;
					break;
				}
			}
			
			if ( $ik ) {
				$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $pike_tables[$key] WHERE `intip` = %s OR `provider` = %s", array($ip_long, $ik)), ARRAY_A);
				if ( $row === NULL ) {
					$sql = $wpdb->prepare("INSERT INTO $pike_tables[$key] (`intip`, `provider`) VALUES(%s, %s)", $ip_long, $ik);
					$wpdb->query($sql);
					return TRUE;
				} else {
					return FALSE;
				}
			} else {
				return FALSE;
			}
		break;
		
		default: 
			return TRUE;
	}
}

/**
 * Plugin shortcode replace
 * 
 * @param string $msg The message
 * @param string $ip_address The IP address
 * 
 * @return string
 */ 
function pike_shortcode_replace($msg="", $ip_address="") {
	$onion = "<img src='data:image/jpeg;base64,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' />";
	$replace_str = str_replace(array('[pike_firewall_logo]', '[ip_address]'), array($onion, $ip_address), $msg);
	return $replace_str;
}

/**
 * Error notices HTML print
 * 
 * @param string $msg The message
 * @param string $class
 * @param string $dismissable
 * 
 * @return void
 */ 
function pike_error_notice($msg="", $class="notice-success", $dismissable="is-dismissible") {
?>		
	<div class="<?php echo 'notice '.$class.' '.$dismissable; ?> pike-firewall-notice">
		<p><?php _e($msg); ?></p>
	</div>
<?php
}

/**
 * Retrieve plugin logs from database
 * 
 * @param string $key The key for the tables array
 * 
 * @return array
 */ 
function pike_get_logs($key) {
	global $wpdb, $pike_tables;
	
	$result = $wpdb->get_results("SELECT * FROM $pike_tables[$key] ORDER BY id DESC", ARRAY_A);
	return $result;
}

/**
 * Save logs in database
 * 
 * @param string $key The key for the tables array
 * @param string $ip_address The IP address
 * @param string $type Type of the request
 * @param string $page The URL of the page visited
 * 
 * @return void
 */ 
function pike_save_logs($key, $ip_address="", $type="", $page="") {
	global $wpdb, $pike_tables;
	
	if ( strlen($ip_address) > 0 ) {
		if ( !$wpdb->insert($pike_tables[$key], array('ip' => $ip_address, 'landing_page' => $page, 'type' => $type), array('%s', '%s', '%s'))) {
			$wpdb->show_errors();
			wp_die($wpdb->print_error());
		}
	}
}

/**
 * Filesystem scan
 * 
 * @return void
 */ 
function pike_file_scan() {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);	
		
	if ( !function_exists('get_home_path') ) {
		require_once ABSPATH.'wp-admin/includes/file.php';
	}
	
	if ( !function_exists('wp_salt') ) {
		require_once ABSPATH.'wp-includes/pluggable.php';
	}
	
	$root = rtrim(get_home_path(), '/');
	$salt = wp_salt();
	$files = array('new' => array(), 'modified' => array(), 'non_modified' => array(), 'deleted' => array(), 'skipped' => array(), 'denied' => array());
	$allowed_extensions = array('php', 'js', 'html', 'css', 'xml');
	$skip_arr = array();
	$merge_arr = array();
	$check = false;
	
	$skip = $pike_options['file_scan']['directory'];
	if ( strlen($skip) > 0 ) {
		$skip_arr = explode(',', $skip);
	}
	
	$iter = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS | RecursiveDirectoryIterator::UNIX_PATHS),
			RecursiveIteratorIterator::SELF_FIRST,
			RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
	);
	
	$row = pike_do_fscanner_data('select');
	if ( $row != NULL ) {
		$data = json_decode($row['files'], true);
		$merge_arr = array_merge($data['new'], $data['modified'], $data['non_modified'], $data['denied'], $data['skipped']);
		$check = true;
	}
	
	clearstatcache();
	foreach ( $iter as $path => $dir ) 	{	
		$ext = pathinfo($path, PATHINFO_EXTENSION);
		if ( $dir->isFile() && !in_array($ext, $allowed_extensions) ) {
			continue;
		}
		
		$symlink = ( $dir->isLink() === true ) ? 1 : 0;
		$is_file = ( $dir->isFile() === true ) ? 1 : 0;

		$path_cmp = trim(str_replace(get_home_path(), '', $dir->getPathName()), '/');
		foreach ( $skip_arr as $skip_item ) {
			if ( strstr($path_cmp, trim($skip_item)) !== false ) {
				if ( $check ) {
					foreach ( $merge_arr as $key => $value ) {
						if ( $key === $path_cmp ) {
							$files['skipped'][$path_cmp] = $merge_arr[$path_cmp];
							unset($merge_arr[$path_cmp]);
							break;
						}
					}
				} else {
					$files['skipped'][$path_cmp] = array('content_hash' => "", 'all_hash' => "", 'is_file' => $is_file, 'symlink' => $symlink);
				}
				continue 2;
			}
		}
		
		$file_content = "";
		$hashed_fcontent = "";
		$all_content = "";
		$hashed_acontent = "";
		
		if ( $dir->isReadable() ) {
			if ( $dir->isFile() ) {
				$fh = @fopen($path, 'r');
				while ( ($line = @fgets($fh, 4096)) !== false ) {
					$file_content .= $line;
				}
				$file_content .= $salt;
				@fclose($path);
			} elseif ( $dir->isDir() ) {
				$dh = @scandir($path);
				$dir_excl = array_diff($dh, array('.', '..'));
				foreach ( $dir_excl as $dir ) {
					$file_content .= $dir;
				}
				$file_content .= $salt;
			}
		}
		
		if ( strlen($file_content) > 0 ) {		
			$hashed_fcontent = sha1($file_content);
			//$all_content = fileatime($path).filemtime($path).filectime($path).filesize($path).$path_cmp.$file_content;
			$all_content = fileatime($path).filectime($path).filesize($path).$path_cmp.$file_content;
			$hashed_acontent = sha1($all_content);
		} else {
			if ( array_key_exists($path_cmp, $merge_arr) ) {
				$files['denied'][$path_cmp] = $merge_arr[$path_cmp];
				unset($merge_arr[$path_cmp]);
			} else {
				if ( !array_key_exists($path_cmp, $files['skipped']) ) {
					$files['denied'][$path_cmp] = array('content_hash' => "", 'all_hash' => "", 'is_file' => $is_file, 'symlink' => $symlink);
				}
			}
			continue;
		}
		
		if ( $check ) {
			if ( array_key_exists($path_cmp, $merge_arr) ) {
				if ( strlen($merge_arr[$path_cmp]['content_hash']) > 0 && strlen($merge_arr[$path_cmp]['all_hash']) > 0 ) {
					if ( $merge_arr[$path_cmp]['content_hash'] != $hashed_fcontent || $merge_arr[$path_cmp]['all_hash'] != $hashed_acontent ) {
						$files['modified'][$path_cmp] = array('content_hash' => $hashed_fcontent, 'all_hash' => $hashed_acontent, 'is_file' => $is_file, 'symlink' => $symlink);
					} else {
						$files['non_modified'][$path_cmp] = array('content_hash' => $merge_arr[$path_cmp]['content_hash'], 'all_hash' => $merge_arr[$path_cmp]['all_hash'], 'is_file' => $merge_arr[$path_cmp]['is_file'], 'symlink' => $merge_arr[$path_cmp]['symlink']);
					}
				} else {
					$files['new'][$path_cmp] = array('content_hash' => $hashed_fcontent, 'all_hash' => $hashed_acontent, 'is_file' => $is_file, 'symlink' => $symlink);
				}
				unset($merge_arr[$path_cmp]);
			} else {
				$files['new'][$path_cmp] = array('content_hash' => $hashed_fcontent, 'all_hash' => $hashed_acontent, 'is_file' => $is_file, 'symlink' => $symlink);
			}
		} else {
			if ( !array_key_exists($path_cmp, $files['skipped']) && !array_key_exists($path_cmp, $files['denied']) ) {
				$files['new'][$path_cmp] = array('content_hash' => $hashed_fcontent, 'all_hash' => $hashed_acontent, 'is_file' => $is_file, 'symlink' => $symlink);
			}
		}
	}

	if ( is_array($merge_arr) && sizeof($merge_arr) > 0 ) {
		foreach ( $merge_arr as $key => $value ) {
			$skip_check = false;
			foreach ( $skip_arr as $skip_item ) {
				if ( strstr($key, trim($skip_item)) !== false ) {
					$files['skipped'][$key] = $value;
					$skip_check = true;
					break;
				}
			}
			
			if ( !$skip_check ) {
				$files['deleted'][$key] = $value;
			}
		}
	}
	
	if ( is_array($files) && sizeof($files) > 0 ) {
		pike_do_fscanner_data('insert', $files);
	}
	
	echo json_encode($files);
}

/**
 * Filesystem scan database operations
 * 
 * @param string $action Database operation
 * @param array $files Array of files
 * 
 * @return array|boolean
 */ 
function pike_do_fscanner_data($action, $files=array()) {
	global $wpdb, $pike_tables;
	
	switch ($action) {
		case 'select':
			$row = $wpdb->get_row("SELECT * FROM ".$pike_tables['filesystem_scan']." ORDER BY time_created DESC", ARRAY_A);
			return $row;
		break;
		
		case 'insert':
			return $wpdb->insert($pike_tables['filesystem_scan'], array('files' => json_encode($files)), array('%s'));
		break;
			
		default:
			return FALSE;
	}
}

/**
 * Apache logs parser
 * 
 * @param string $file The filename
 * 
 * @return array
 */ 
function pike_parse_log_file($file="") {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$log_file = $file;
	$pattern = '/^((?:[0-9]{1,3}\.){3}[0-9]{1,3}) (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\S+) (\S+) "([^"]*)" "([^"]*)"$/';
	$pattern_404 = '/^((?:[0-9]{1,3}\.){3}[0-9]{1,3}){1} (\S+) (\S+) \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\S+) (\S+)( "([^"]*)" "([^"]*)")?$/';

	$fp = @fopen($log_file, 'r');
	$analyze = array();
	$i = 1;

	while ( !feof($fp) ) {
		// Read each line and trim off leading/trailing whitespace
		if ( $line = trim(fgets($fp, 16384)) ) {
			// Match the line to the pattern
			if ( preg_match($pattern, $line, $matches) ) {
				// Put each part of the match in an appropriate variable
				list($whole_match, $remote_host, $logname, $user, $date, $time, $timezone, $method, $request, $protocol, $status, $bytes, $referer, $user_agent) = $matches;
				$url = parse_url($request);
				$valid_time = strtotime(DateTime::createFromFormat('d/M/Y H:i:s', $date.' '.$time)->format('Y/m/d H:i:s'));
				if ( time() - $valid_time <= strtotime('2 days', 0) ) {
					$analyze[] = pike_log_analyze($whole_match, $remote_host, $user_agent);
				}
			} elseif ( preg_match($pattern_404, $line, $matches) ) {
				list($whole_match, $remote_host, $logname, $user, $date, $time, $timezone, $method, $request, $protocol, $status, $bytes) = $matches;
				$url = parse_url($request);
				$valid_time = strtotime(DateTime::createFromFormat('d/M/Y H:i:s', $date.' '.$time)->format('Y/m/d H:i:s'));
				if ( time() - $valid_time <= strtotime('2 days', 0) ) {
					$analyze[] = pike_log_analyze($whole_match, $remote_host);
				}
			}
		}
		$i++;
	}

	@fclose($fp);
	return $analyze;
}

/**
 * Apache logs analyzer
 * 
 * @param string $line Line of the file being analyzed
 * @param string $ip The IP address
 * @param string $ua The user agent
 * 
 * @return array
 */ 
function pike_log_analyze($line, $ip_address, $ua="") {
	global $pike_settings, $pike_agent;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$ip_long = ip2long($ip_address);
	$tmp = array();
	$found = false;

	if ( !$found && isset($pike_options['analyze']['tor_proxy']) ) {
		if ( pike_get_table_data('single_ip', $ip_long) !== NULL && 
			 pike_get_table_data('crawl_fake_ip', $ip_long) === NULL ) {
			
			$tmp = array('IP' => $ip_address, 'type' => "TP", 'line' => $line);
			$found = true;
		}
	} 
		
	if ( !$found && isset($pike_options['analyze']['datacenters']) ) {
		if ( pike_get_table_data('range_ip', $ip_long) !== NULL ) {
			$tmp = array('IP' => $ip_address, 'type' => "DC", 'line' => $line);
			$found = true;
		}
	}
		
	if ( !$found && isset($pike_options['analyze']['crawlers_v']) ) {
		if ( pike_get_table_data('crawl_ip', $ip_long) !== NULL ||
			 pike_get_table_data('crawl_range_ip', $ip_long) !== NULL ) 
		{
			$tmp = array('IP' => $ip_address, 'type' => "VC", 'line' => $line);
			$found = true;
		}
	}
		
	if ( !$found && isset($pike_options['analyze']['crawlers_f']) ) {
		if ( pike_get_table_data('crawl_fake_ip', $ip_long) !== NULL ) {
			$tmp = array('IP' => $ip_address, 'type' => "FC", 'line' => $line);
			$found = true;
		}
	}
		
	if ( !$found ) {
		if ( ($user_agent = pike_get_vendor($pike_agent)) !== false ) {
			if ( $user_agent == 'facebook' || pike_check_FCrDNS($user_agent, $ip_address) ) {
				if ( isset($pike_options['analyze']['crawlers_v']) ) {
					$tmp = array('IP' => $ip_address, 'type' => "VC", 'line' => $line);
				}
			} else {
				if ( isset($pike_options['analyze']['crawlers_f']) ) {
					$tmp = array('IP' => $ip_address, 'type' => "FC", 'line' => $line);
				}
			}
			$found = true;
		}
	}

	return $tmp;
}

/**
 * Plugin logs parser
 * 
 * @param string $ip_address The IP address
 * @param string $type Type of the request
 * @param boolean $crawler_check Whether it is a crawler or not
 * 
 * @return void
 */ 
function pike_parse_log($ip_address, $type="", $crawler_check=false) {		
	$table_key = ( $crawler_check === true ) ? 'log_crawlers' : 'log';	
	$page_url = pike_get_url();
	pike_save_logs($table_key, $ip_address, $type, $page_url);
}

/**
 * Get the visited URL along with all GET, POST and COOKIE parameters
 * 
 * @return string The page URL with all of the request parameters
 */ 
function pike_get_url() {
	$page_url = urlencode("http".(!empty($_SERVER['HTTPS']) ? 's' : '')."://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
	
	if ( !empty($_POST) ) {
		$post_arr = stripslashes_deep($_POST);
		$page_url .= "\nPOST: ";
		foreach ( $post_arr as $kpost => $post ) {
			$page_url .= $kpost."=".$post.", ";
		}	
		$page_url = rtrim($page_url, ", ");
	}	
		
	if ( !empty($_GET) ) {
		$get_arr = stripslashes_deep($_GET);
		$page_url .= "\nGET: ";
		foreach ( $get_arr as $kget => $get ) {
			$page_url .= $kget."=".$get.", ";
		}
		$page_url = rtrim($page_url, ", ");
	}
		
	if ( !empty($_COOKIE) ) {
		$cookie_arr = stripslashes_deep($_COOKIE);
		$page_url .= "\nCOOKIE: ";
		foreach ( $cookie_arr as $kcookie => $cookie ) {
			$page_url .= $kcookie."=".$cookie.", ";
		}
		$page_url = rtrim($page_url, ", ");
	}
	
	return $page_url;
}

/**
 * Filter function to change uploads directory path
 * 
 * @param array $upload
 * 
 * @return array
 */ 
function pike_get_upload_dir($upload) {
	$upload['subdir'] = '/pike_firewall/logs';
	$upload['path']   = $upload['basedir'].$upload['subdir'];
	$upload['url']    = $upload['baseurl'].$upload['subdir'];
	return $upload;
}
	
/**
 * Filter function to change uploads allowed MIME types
 * 
 * @param array $mime_types
 * 
 * @return array
 */ 
function pike_change_mimes($mime_types) {
	$mime_types['log'] = 'text/plain';
	foreach ( $mime_types as $key => $value ) {
		if ( $value == 'text/plain' )	{
			continue;	
		}
		unset($mime_types[$key]);
	}
	return $mime_types;
}

/**
 * Check Refferer
 * 
 * @param string $host
 * 
 * @return boolean
 */ 
function pike_check_post_referer($host="localhost") {
	if ( isset($_POST) && sizeof($_POST) > 0 ) {
		if ( isset($_SERVER['HTTP_REFERER']) && trim($_SERVER['HTTP_REFERER']) != "" ) {
			$r = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
			$r = str_replace('www.', '', strtolower($r));
			$host = str_replace('www.', '', strtolower($host));
			if ( $r == $host ) {
				return TRUE;
			} else {
				return FALSE;
			}
		} else {
			return FALSE;
		}
	} else {
		return TRUE;
	}
}

/**
 * Check for blank User-Agent
 * 
 * @return boolean
 */
function pike_check_post_ua() {
	if ( isset($_SERVER['HTTP_USER_AGENT']) && trim($_SERVER['HTTP_USER_AGENT']) != "" && strlen(trim($_SERVER['HTTP_USER_AGENT'])) > 5 ) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Check for User-Agent set by cmd Browser or Software library
 * 
 * @return boolean
 */ 
function pike_check_post_ua_cmd() {
	$check_ua = pike_get_ua_cmd($_SERVER["HTTP_USER_AGENT"]);
	if ( isset( $_SERVER["HTTP_USER_AGENT"] ) && trim($_SERVER["HTTP_USER_AGENT"]) != "" && strlen(trim($_SERVER["HTTP_USER_AGENT"])) > 5 && !$check_ua ) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * Get cmd Browser / Software library
 * 
 * @param string $ua The user agent
 * 
 * @return string|boolean
 */ 
function pike_get_ua_cmd($ua="") {
	$ua_identification_strings = array(
		'wpscan' => array('wpscan'),
		'binget' => array('binget'),
		'curl' => array('curl'),
		'java' => array('java'),
		'libwww-perl' => array('libwww-perl'),
		'microsoft' => array('microsoft%20url%20control'),
		'peach' => array('peach'),
		'php' => array('php'),
		'pxyscand' => array('pxyscand'),
		'pycurl' => array('pycurl'),
		'pyrhon-urllib' => array('python-urllib'),
		'appengine-google' => array('appengine-google'),
		'links' => array('links'),
		'links2' => array('links2'),
		'elinks' => array('elinks'),
		'w3m' => array('w3m'),
		'lynx' => array('lynx'),
		'retawq' => array('retawq'),
		'wget' => array('wget')
	);
	
	$ua = strtolower($ua);
	foreach ( $ua_identification_strings as $vendor => $pattern ) {
		if ( is_array($pattern) && sizeof($pattern) > 0 ) {
			foreach ( $pattern as $pi ) {
				if ( strpos($ua, $pi) !== FALSE ) {
					return $vendor;
				}
			}
		}
	}
	
	return FALSE;
}

/**
 * Check for Wordress User Enumeration
 * 
 * @return boolean
 */ 
function pike_check_user_enum() {
	if ( !is_admin() ) {
		if ( isset($_SERVER['REQUEST_URI']) && trim($_SERVER['REQUEST_URI']) != "" ) {
			if ( strpos(strtolower($_SERVER['REQUEST_URI']), 'wp-comments-post') !== false ) {
				if ( is_array($_REQUEST) && sizeof($_REQUEST) > 0 ) {
					foreach ( $_REQUEST as $key => $val ) {
						if ( strtolower($key) == 'author' ) {
							return FALSE;
						}
					}
				} else {
					if ( is_array($_GET) && sizeof($_GET) > 0 ) {
						foreach ( $_GET as $key => $val ) {
							if ( strtolower($key) == 'author' ) {
								return FALSE;
							}
						}
					}
					if ( is_array($_POST) && sizeof($_POST) > 0 ) {
						foreach ( $_POST as $key => $val ) {
							if ( strtolower($key) == 'author' ) {
								return FALSE;
							}
						}
					}
				}
			}
		}
	}
	
	if ( isset($_SERVER['QUERY_STRING'] ) && trim($_SERVER['QUERY_STRING']) != "" && strpos($_SERVER['QUERY_STRING'], 'author') !== false ) {
		if ( is_array($_GET) && sizeof($_GET) > 0 ) {
			foreach ( $_GET as $key => $val ) {
				if ( strtolower($key) == 'author' ) {
					if ( is_numeric($_GET[$key]) ) {
						return FALSE;
					}
				}
			}
		}
	}
	
	if ( isset($_SERVER['REQUEST_URI']) && trim($_SERVER['REQUEST_URI']) != "" ) {
		$t = explode('/', $_SERVER['REQUEST_URI']);
		if ( is_array($t) && sizeof($t) > 1 ) {
			$f = false;
			foreach( $t as $item ) {
				if ( strtolower($item) == 'author'  ) {
					$f = true;
				}
				if ( $f && is_numeric($item) ) {
					return FALSE;
				}
			}
		}
	}
	
	return TRUE;
}

/**
 * Proxy Headers check
 * 
 * @return boolean
 */ 
function pike_check_proxy_by_headers() {
	$p_headers = array(
		'CLIENT_IP',
		'FORWARDED',
		'FORWARDED_FOR',
		'FORWARDED_FOR_IP',
		'HTTP_CLIENT_IP',
		'HTTP_FORWARDED',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED_FOR_IP',
		'HTTP_PC_REMOTE_ADDR',
		'HTTP_PROXY_CONNECTION',
		'HTTP_VIA',
		'HTTP_X_FORWARDED',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED_FOR_IP',
		'HTTP_X_IMFORWARDS',
		'HTTP_XROXY_CONNECTION',
		'VIA',
		'X_FORWARDED',
		'X_FORWARDED_FOR'
	);
	
	foreach( $p_headers as $ph ) {
		if ( isset($_SERVER[$ph]) ) {
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Check Forward and Reverse DNS
 * 
 * @param string $user_agent
 * @param string $ip_address
 * 
 * @return boolean
 */
function pike_check_FCrDNS($user_agent="", $ip_address=NULL) {
	$tmp1 = pike_check_RDNS($user_agent, $ip_address);
	if ( $tmp1 ) {
		$tmp2 = pike_check_FDNS($tmp1['HOST'], $ip_address);
		if ( $tmp2 ) {
			if ( $tmp1['IP'] == $tmp2['IP'] && $tmp1['HOST'] == $tmp2['HOST'] ) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Check Reverse DNS
 * 
 * @param string $user_agent
 * @param string $ip_address
 * 
 * @return array|boolean
 */ 
function pike_check_RDNS($user_agent="", $ip_address=NULL) {
	$crawlers_identification_domains = array(
		'google' => '/\.(?:googlebot\.com|google\.com|google\.co\.uk|google\.co\.in)$/i',
		'bing'   => '/\.search\.msn\.com$/i',
		'yahoo'  => '/\.crawl\.yahoo\.net$/i',
		'yandex' => '/\.(?:yandex\.ru|yandex\.com|yandex\.net)$/i'
		// SHOULD DO FOR FACEBOOK TOO?
	);
	
	$regex = $crawlers_identification_domains[$user_agent];
	// Add verification for the ip
	if ( function_exists('gethostbyaddr') ) {
		$host = gethostbyaddr($ip_address);
		if ( preg_match($regex, $host) ) {
			return array('IP' => $ip_address, 'HOST' => $host);
		}
	}
	
	return FALSE;
}

/**
 * Check Forward DNS
 * 
 * @param string $host
 * @param string $ip_address
 * 
 * @return array|boolean
 */
function pike_check_FDNS($host="", $ip_address=NULL) {
	$out = array();
	if ( !function_exists('dns_get_record') ) {
		$out = gethostbynamel($host);
	} else {
		$ipa = (array) dns_get_record($host, DNS_A);
		foreach ( $ipa as $ipr ) {
			if ( is_array($ipr) && isset($ipr['type']) && isset($ipr['ip']) ) {
				if ($ipr['type'] === 'A') {
					$out[] = $ipr['ip'];
				}
			}
		}	
	}
	
	if ( is_array($out) && sizeof($out) > 0 ){
		$f = false;
		foreach ( $out as $ipll ) {
			if ( $ipll == $ip_address ){
				$f = true;
				return array('IP' => $ip_address, 'HOST' => $host);
			}
		}
	}
	
	return FALSE;
}

/**
 * Merge plugin IP tables
 * 
 * @return void
 */ 
function pike_merge_db_singleip_crawlerip() {
	global $wpdb, $pike_tables;

	$insert = "";
	$tmp = array();

	$crawlers = $wpdb->get_results("SELECT intip FROM $pike_tables[crawl_fake_ip] WHERE timecreated > DATE_SUB(CURDATE(), INTERVAL 1 WEEK)", ARRAY_A);
	if ( is_array($crawlers) && sizeof($crawlers) > 0 ) {
		foreach ( $crawlers as $crawler ) {
			$long_ip = $crawler['intip'];
			if ( $long_ip > 0 && !in_array($long_ip, $tmp) ) {
				$single_ip = $wpdb->get_row($wpdb->prepare("SELECT `ip` FROM $pike_tables[single_ip] WHERE `ip` = %s", $long_ip), ARRAY_A);
				if ( $single_ip === NULL ) {
					$wpdb->prepare("(%s), ", $long_ip);
					$tmp[] = $long_ip;
				}
			}
		}
		
		if ( sizeof($tmp) > 0 && strlen($insert) > 0 ) {
			$insert = rtrim($insert, ', ');
			$wpdb->query("INSERT INTO ".$pike_tables['single_ip']." (`ip`) VALUES $insert");
		}
	}
}

/**
 * Append two arrays
 * 
 * @param array $arr1
 * @param array $arr2
 * 
 * @return array|int
 */ 
function pike_append_arrays($arr1, $arr2) {
	$out_arr = array();
	if ( is_array($arr1) && is_array($arr2) && sizeof($arr2) > 0 ) {
		foreach ( $arr1 as $key => $val ) {
			if ( !in_array($val, $out_arr) ) {
				$out_arr[] = $val;
			}
		}
		
		foreach ( $arr2 as $key => $val ) {
			if ( !in_array($val, $out_arr) ) {
				$out_arr[] = $val;
			}
		}
		
		if ( sizeof($out_arr) > 0 ) {
			return $out_arr;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

/**
 * Add CSS for the plugin log tables
 * 
 * @return void
 */ 
function pike_admin_header() {
	$page = isset($_GET['page']) ? esc_attr($_GET['page']) : false;
	$active_tab = isset($_GET['tab']) ? esc_attr($_GET['tab']) : false;
	if ( 'pike_firewall' != $page ) {
   		return; 
	}

	if ( $active_tab == 'logs' || $active_tab == 'crawlers' ) {
		echo '<style type="text/css">';
	  	//echo '.wp-list-table td { vertical-align:middle; }';
	  	echo '.wp-list-table .column-ip { width:15%; }';
	 	echo '.wp-list-table .column-ladning_page { width:55%; }';
	 	echo '.wp-list-table .column-type { width:15%; }';
	 	echo '.wp-list-table .column-systime { width:15%; }';
	 	echo '</style>';
  	} elseif ( $active_tab == 'filesystem_logs' ) {
		echo '<style type="text/css">';
	 	echo '.wp-list-table td { vertical-align:middle; }';
	  	echo '.wp-list-table .column-name { width:70%; }';
	 	echo '.wp-list-table .column-directory { width:10%; }';
	 	echo '.wp-list-table .column-type { width:10%; }';
	 	echo '.wp-list-table .column-symlink { width:10%; }';
	 	echo '</style>';
  	} elseif ( $active_tab == 'login_attempts' ) {
  		echo '<style type="text/css">';
	  	echo '.wp-list-table .column-username { width:10%; }';
	 	echo '.wp-list-table .column-user_address { width:15%; }';
	 	echo '.wp-list-table .column-user_agent { width:40%; }';
	 	echo '.wp-list-table .column-login_time { width:15%; }';
	 	echo '.wp-list-table .column-type { width:20%; }';
	 	echo '.wp-list-table .column-success { width:10%; }';
	 	echo '</style>';
  	}
}



/**
 * Track failed logins
 * 
 * @param string $username
 * 
 * @return void
 */ 
function pike_login_failed($username) {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['login_attempts']) ) {
		$success = 0;
		pike_login_attempt($username, $success);
	}
}

/**
 * Track successful logins
 * 
 * @param string $username
 * @param object $user
 * 
 * @return void
 */ 
function pike_login_success($username, $user) {
	global $pike_settings;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	if ( isset($pike_options['login_attempts']) ) {
		$success = 1;
		pike_login_attempt($username, $success);
	}
}
	
/**
 * Insert login attempts into database
 * 
 * @param string $username
 * @param int $success
 * 
 * @return void
 */ 
function pike_login_attempt($username="", $success=0) {
	global $wpdb, $pike_tables, $pike_ip, $pike_agent;
	
	if ( !empty($username) ) {
		$type = "Regular";
		if ( pike_ip != $_SERVER['SERVER_ADDR'] ) {
			if ( ($match_data = pike_match_ip()) !== FALSE ) {
				$type = $match_data['type'];
			} else {
				$wphost = parse_url(site_url(), PHP_URL_HOST);
				if ( ($vendor = pike_get_vendor($pike_agent)) !== FALSE ) {
					if ( pike_check_whitelist(ip2long($pike_ip)) === FALSE ) {
						if ( !($vendor == "facebook" || pike_check_FCrDNS($vendor, $pike_ip)) ) {
							$type = 'Fake Crawler';
						}
					}
				} else if ( !pike_check_post_ua() ) {
					$type = 'Blank User Agent';
				} else if ( !pike_check_post_ua_cmd() ) {
					$type = 'cmd Browser / Software Library';
				} else if ( !pike_check_proxy_by_headers() ) {
					$type = 'Proxy Headers';
				} else if ( !pike_check_post_referer($wphost) ) {
					$type = 'Foreign Origin';
				} else if ( !pike_check_user_enum() ) {
					$type = 'User Enumeration';
				}
			}	
			
			if ( $success === 0 && isset($pike_options['send_email'][6]) ) {
				$notification_title = "User login: $type";
				pike_notifications($notification_title);
			}
		
			if ( !$wpdb->insert($pike_tables['login'], array('username' => $username, 'user_address' => $pike_ip, 'user_agent' => $pike_agent, 'type' => $type, 'success' => $success), array('%s', '%s', '%s'))) {
				$wpdb->show_errors();
				wp_die($wpdb->print_error());
			}
		}
	}		
}

/**
 * Send email/notifications to the admin for suspicious vistis and actions
 * 
 * @param string $subject
 * @param string $type
 * 
 * @return boolean
 */ 
function pike_notifications($subject="Pike Firewall Notification", $type="email") {
	global $pike_settings, $pike_ip, $pike_agent;
	$pike_options = get_option('pike_firewall', $pike_settings);
	
	$page_url = pike_get_url();
	$content = "<body><h3>Suspicious action detected!</h3><p><strong>IP:</strong> ".esc_html($pike_ip)."</p><p><strong>User-Agent:</strong> ".esc_html($pike_agent)."</p><p><strong>URL and Request:</strong><br/>".nl2br(esc_html(urldecode($page_url)))."</p></body>";
	
	$status = false;
	if ( $type == 'email' && is_email($pike_options['send_email']['recipient']) && !empty($subject) && !empty($content) ) {
		if ( !function_exists('wp_mail') ) {
			require_once ABSPATH.'wp-includes/pluggable.php';
		}
	
		$to = sanitize_email($pike_options['send_email']['recipient']);
		$headers = array('Content-Type: text/html; charset=UTF-8');
		
		add_filter('wp_mail_from_name', 'pike_set_mail_name');
		$status = wp_mail($to, $subject, $content, $headers);
		remove_filter('wp_mail_from_name', 'pike_set_mail_name');
	}
	
	return $status;
}

/**
 * Set mail subject
 * 
 * @return void
 */ 
function pike_set_mail_name() {
	return 'Pike Firewal';
}
