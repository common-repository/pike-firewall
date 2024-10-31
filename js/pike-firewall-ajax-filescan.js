jQuery(document).ready( function() {
	jQuery(".pike-firewall-file-scan").click( function() {
		var nonce = jQuery(this).attr('data-nonce');
		jQuery('.loading').html('Loading data. Please wait...');
		jQuery('.scan-results').empty();
		jQuery.ajax({
			type: 'post',
			url: pikefirewallAJAXScan.ajaxurl,
			data: { action: 'pike_firewall_ajax_filescan', nonce: nonce },
			dataType: 'json',
			success: function(response) {
//				console.log(response);
				
				var html = '';
				var title = '';
				var total_keys = 0;
				var total = 0;
				
				jQuery('.loading').empty();
				for ( var key in response ) {
					switch (key) {
						case 'new':
							title = 'New files/directories:';
							total_keys = Object.keys(response[key]).length;
							total += total_keys;
							html = html.concat('<label><strong>' + title + '</strong> ' + total_keys + '</label><br/>');
						break;
						
						case 'modified':
							title = 'Modified files/directories:';
							total_keys = Object.keys(response[key]).length;
							total += total_keys;
							html = html.concat('<label><strong>' + title + '</strong> ' + total_keys + '</label><br/>');
						break;
						
						case 'denied':
							title = 'Denied files/directories:';
							total_keys = Object.keys(response[key]).length;
							total += total_keys;
							html = html.concat('<label><strong>' + title + '</strong> ' + total_keys + '</label><br/>');
						break;
						
						case 'deleted':
							title = 'Deleted files/directories:';
							total_keys = Object.keys(response[key]).length;
							total += total_keys;
							html = html.concat('<label><strong>' + title + '</strong> ' + total_keys + '</label><br/>');
						break;
						
						case 'skipped':
							title = 'Skipped files/directories:';
							total_keys = Object.keys(response[key]).length;
							html = html.concat('<label><strong>' + title + '</strong> ' + total_keys + '</label><br/>');
						break;
						
						case 'non_modified':
							total_keys = Object.keys(response[key]).length;
							total += total_keys;
						break;
					}
				}
				
				str = '<label><strong>Total number of files and directories scanned:</strong> ' + total + '</label><br/>';
				html = str.concat(html);
				
				jQuery('.scan-results').html('Scan completed successfully. To see the results, go to the File Scan Logs tab.<br/><br/>Summary:<br/>' + html);
			},
			error: function (err) {
//				console.log(err.responseText);
				jQuery('.loading').empty();
				jQuery('.scan-results').html('Scan did not completed due to the following error: <strong>' + ( (err.responseText === 0) ? 'unknown' : err.responseText ) + '</strong');
			}
		})   
	})
})