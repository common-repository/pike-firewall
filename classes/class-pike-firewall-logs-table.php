<?php
class Pike_Firewall_Logs_Table extends WP_List_Table_Copy {
	protected $table_name;
	protected $per_page;
	
	public function __construct() {
		parent::__construct(array(
			'singular'	=> 'pike-firewall-table',
			'plural'	=> 'pike-firewall-tables',
			'ajax'		=> false
		));
		
		$options = array(
			's' => ( !empty($_REQUEST['s']) ) ? $_REQUEST['s'] : ""
		);
		
		// Update the current URI with the new options
		$_SERVER['REQUEST_URI'] = ( !empty($options['s']) ) ? add_query_arg($options, $_SERVER['REQUEST_URI']) : remove_query_arg('s', $_SERVER['REQUEST_URI']);
		$this->per_page = 25;
	}
	
	public function set_db_table_name($table_name) {
		$this->table_name = $table_name;
	}
	
	// Prepare the table with different parameters, pagination, columns and table elements
	public function prepare_items() {
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		if ( $active_tab == 'logs' || $active_tab == 'crawlers' || $active_tab == 'login_attempts' ) {
			$this->process_logs_crawlers_login();
		} elseif ( $active_tab == 'filesystem_logs' ) {
			$this->process_filesystem_logs();
		}
	}
	
	public function get_columns() {
		$columns = array();
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		if ( $active_tab == 'logs' || $active_tab == 'crawlers' ) {
			$columns = array(
				'cb' 			=> '<input type="checkbox" />',
				'ip' 			=> __('IP'),
				'landing_page' 	=> __('URL'),
				'type' 			=> __('Type'),
				'systime' 		=> __('Time')
			);
		} elseif ( $active_tab == 'filesystem_logs' ) {
			$columns = array(
				'name' 		=> __('Name'),
				'directory' => __('Dir/File'),
				'type' 		=> __('Type'),
				'symlink' 	=> __('Symlink')
			);
		} elseif ( $active_tab == 'login_attempts' ) {
			$columns = array(
				'cb' 			=> '<input type="checkbox" />',
				'username' 		=> __('Username'),
				'user_address' 	=> __('IP'),
				'user_agent' 	=> __('User-Agent'),
				'type' 			=> __('Type'),
				'success'		=> __('Logged in'),
				'login_time'	=> __('Time')
			);
		}
		return $columns;
	}
	
	public function get_sortable_columns() {
		$sortable_columns = array();
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		if ( $active_tab == 'logs' || $active_tab == 'crawlers' ) {
			$sortable_columns = array(
				'ip' 		=> array('ip', true),
				'type' 		=> array('type', true),
				'systime' 	=> array('systime', true)
			);
		} elseif ( $active_tab == 'filesystem_logs' ) {
			$sortable_columns = array(
				'name' 		=> array('name', true),
				'directory' => array('directory', true),
				'type' 		=> array('type', true),
				'symlink' 	=> array('symlink', true)
			);
		} elseif ( $active_tab == 'login_attempts' ) {
			$sortable_columns = array(
				'username' 		=> array('username', true),
				'user_address' 	=> array('user_address', true),
				'user_agent' 	=> array('user_agent', true),
				'type' 		=> array('type', true),
				'success'		=> array('success', false),
				'login_time'	=> array('login_time', true)
			);
		}
		return $sortable_columns;
	}
	
	public function get_bulk_actions() {
		$actions = array();
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		if ( $active_tab == 'logs' || $active_tab == 'crawlers' || $active_tab == 'login_attempts' ) {
			$actions = array(
	    		'bulk-delete'    => 'Delete'
	  		);
		}
		return $actions;
	}
	
	public function column_default($item, $column_name) {
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		if ( $active_tab == 'logs' || $active_tab == 'crawlers' ) {
			switch ( $column_name ) { 
	    		case 'ip':
	    		case 'type':
	    		case 'systime':
	     	 		return esc_html($item[$column_name]);
	    		break;
	    		
	    		case 'landing_page':
	    			return nl2br(esc_html(urldecode($item[$column_name])));
	    		break;
	    			
	     	 	default:
	      			//return print_r($item, TRUE);	// Show the whole array for troubleshooting purposes
	      			return FALSE;
	  		}
		} elseif ( $active_tab == 'filesystem_logs' ) {
			switch ( $column_name ) { 
	    		case 'name':
	    		case 'type':
	     	 		return esc_html($item[$column_name]);
	    		break;
	    		
	    		case 'directory':
	    		case 'symlink':
	    			return $item[$column_name];
	    		break;
	    			
	     	 	default:
	      			//return print_r($item, TRUE); //show the whole array for troubleshooting purposes
	      			return FALSE;
	  		}
		} elseif ( $active_tab == 'login_attempts' ) {
			switch ( $column_name ) { 
	    		case 'username':
	    		case 'user_address':
	    		case 'user_agent':
	    		case 'login_time':
	    		case 'type':
	     	 		return esc_html($item[$column_name]);
	    		break;
	    		
	    		case 'success':
	    			return ($item[$column_name] == 1) ? '<span style="color:green">Y</span>' : '<span style="color:red">N</span>';
	    		break;
	    			
	     	 	default:
	      			return FALSE;
	  		}
		} else {
			return FALSE;
		}
	}
	
	public function column_cb($item) {
		return sprintf('<input type="checkbox" name="bulk_delete[]" value="%s" />', $item['id']); 
	}

	public function no_items() {
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		if ( $active_tab == 'logs' || $active_tab == 'crawlers' || $active_tab == 'login_attempts' ) {
			_e('No entries to show.');
		} elseif ( $active_tab == 'filesystem_logs' ) {
			_e('No modifications found on the filesystem.');
		}
	}
	
	public function extra_tablenav($which) {
		$active_tab = ( isset($_GET['tab']) ) ? $_GET['tab'] : false;
		
		if ( $which == 'top' ) {
			// Additinal controls between bulk-actions and pagination
			if ( $active_tab == 'logs' || $active_tab == 'crawlers' || $active_tab == 'login_attempts' ) {
				echo '<input type="submit" name="'.( ($active_tab == 'logs') ? 'pike-firewall-csv' : ( ($active_tab == 'crawlers') ? 'pike-firewall-csv-crawlers' : 'pike-firewall-csv-login' ) ).'" class="button" value="Export to CSV" style="margin:3px" />';
			}
		}
		
		if ( $which == 'bottom' ) {
			// Additional controls between-bulk actions and pagination
		}
	}
	
	private function process_logs_crawlers_login() {
		global $wpdb;
								
		//$screen = get_current_screen();
		$this->process_bulk_action();
		$sql = "SELECT * FROM $this->table_name";
		
		if ( !empty($_REQUEST['s']) ) {
			$sql .= " WHERE ";
			$search = $_REQUEST['s'];
			$columns = $this->get_columns();
			$end = sizeof($columns);
			$cnt = 0;
			foreach ( $columns as $column => $title ) {
				$cnt++;
				if ( $column == 'cb' ) {
					continue;
				}
				
				if ( $cnt == $end ) {
					$sql .= $wpdb->prepare($column." LIKE %s", '%'.$search.'%');
				} else {
					$sql .= $wpdb->prepare($column." LIKE %s OR ", '%'.$search.'%');
				}
			}
		}
		
		$order_by = ( !empty($_REQUEST['orderby']) ) ? esc_sql($_REQUEST['orderby']) : "`id`";
		$order = ( !empty($_REQUEST['order']) ) ? esc_sql($_REQUEST['order']) : "DESC";
    	if ( $order_by == 'ip' || $order_by == 'user_address' ) {
    		$sql .= " ORDER BY LPAD($order_by, 16, 0) $order"; 
    	} else {
    		$sql .= " ORDER BY $order_by $order"; 
    	}

    	$per_page = $this->per_page;
		$total_items = $wpdb->query($sql);
		$total_pages = ceil($total_items/$per_page);
		if ( empty($_REQUEST['paged']) || !is_numeric($_REQUEST['paged']) || $_REQUEST['paged'] <= 0 ) {
			$paged = 1;
		} else {
			$paged = (int)$_REQUEST['paged'];
			if ( $paged > $total_pages ) {
				$paged = ( $total_pages > 1 ) ? $total_pages : 1;
			}
		}
		
		$offset = ($paged - 1) * $per_page;
		$sql .= $wpdb->prepare(" LIMIT %d, %d", $offset, $per_page);
			
		$this->set_pagination_args(array(
	    	'total_items' 	=> $total_items,	
			'total_pages'	=> $total_pages,	
	    	'per_page'    	=> $per_page			
	  	));
	  	
	  	$columns = $this->get_columns();
	  	$hidden = array();
	  	$sortable = $this->get_sortable_columns();
	  	$this->_column_headers = array($columns, $hidden, $sortable);
			
		$this->items = $wpdb->get_results($sql, ARRAY_A);
	}
	
	private function process_filesystem_logs() {
		global $wpdb;
		
		//$screen = get_current_screen();
		
		$logs = array();
		$final = array();
		$search = ( !empty($_REQUEST['s']) ) ? $_REQUEST['s'] : "";

		$result = $wpdb->get_results("SELECT * FROM $this->table_name ORDER BY `id` DESC", ARRAY_A);
		if ( is_array($result) && sizeof($result) > 0 ) {
			$tmp = $result[0];
			echo "<br/><label>Last scan: <strong>".esc_html(date('l H:i, F d, Y', strtotime($tmp['time_created'])))."</strong></label>";
			$logs = json_decode($tmp['files'], true);
			foreach ( $logs as $key => $value ) {
				if ( $key == 'non_modified' || $key == 'skipped' ) {
					continue;
				}
				
				foreach ( $value as $k => $v ) {
					if ( empty($search) || strpos($k, $search) !== false || strpos($key, $search) !== false ) {
						$final[] = array('name' => esc_sql($k), 'directory' => ( ( $v['is_file'] === 1 ) ? 'file' : 'dir' ), 'type' => esc_sql(ucfirst($key)), 'symlink' => ( ( $v['symlink'] === 1 ) ? '<span style="color:green">Y</span>' : '<span style="color:red">N</span>' ));
					}
				}
			}
		}
		
		usort($final, array($this, 'usort_reorder'));
		
		$per_page = $this->per_page;
		$total_items = sizeof($final);
		$total_pages = ceil($total_items/$per_page);
		if ( empty($_REQUEST['paged']) || !is_numeric($_REQUEST['paged']) || $_REQUEST['paged'] <= 0 ) {
			$paged = 1;
		} else {
			$paged = (int)$_REQUEST['paged'];
			if ( $paged > $total_pages ) {
				$paged = ( $total_pages > 1 ) ? $total_pages : 1;
			}
		}
		
		$offset = ($paged - 1) * $per_page;	
		$this->set_pagination_args(array(
	    	'total_items' 	=> $total_items,	
			'total_pages'	=> $total_pages,	
	    	'per_page'    	=> $per_page			
	  	));
	  	
	  	$columns = $this->get_columns();
	  	$hidden = array();
	  	$sortable = $this->get_sortable_columns();
	  	$this->_column_headers = array($columns, $hidden, $sortable);
		
		$this->items = array_slice($final, $offset, $per_page);
	}
	
	private function usort_reorder($a, $b) {
		$order_by = ( !empty($_REQUEST['orderby']) ) ? $_REQUEST['orderby'] : 'name';
		$order = ( !empty($_REQUEST['order']) ) ? $_REQUEST['order'] : 'asc';
		$result = strcmp($a[$order_by], $b[$order_by]);
		return ( $order === 'asc' ) ? $result : -$result;
	}
	
	private function process_bulk_action() {
		if ( 'bulk-delete' === $this->current_action() ) {
			$to_delete = ( !empty($_REQUEST['bulk_delete']) ) ? $_REQUEST['bulk_delete'] : array();
			foreach ( $to_delete as $delete ) {
				$this->delete_record(absint($delete));
			}
		}
	}
	
	private function delete_record($id) {
		global $wpdb;
  		$wpdb->delete($this->table_name, array('id' => $id), array('%s'));
	}
}