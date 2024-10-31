<?php if ( !defined('ABSPATH') ) die(); ?>
<form method="post" action="" enctype="multipart/form-data">
	<p>		
		<label><strong>Apache Logs Analyze</strong></label><br/>
		<label><small>Upload an Apache log file to be analyzed:</small></label><br/>
		<input type="file" name="pike-firewall-apache-logfile" />
	</p>
	<p class="submit">
		<input type="submit" name="pike-firewall-apache-log-analyze" class="button-primary" value="Analyze" />
	</p>
	<p>
		<label><strong>Log Analyze Results:</strong></label><br/>
		<label><small>Only logs that are NOT older than two days are analyzed!</small></label><br/>
		<label>Current upload filesize: <?php echo esc_html(ini_get('upload_max_filesize')) ?></label><br/>
		<fieldset>
			<legend>Legend:</legend>
			<strong>TP</strong> = Proxy/Tor&nbsp;&nbsp;
			<strong>DC</strong> = Data Center&nbsp;&nbsp;
			<strong>FC</strong> = Fake Crawler&nbsp;&nbsp;
			<strong>VC</strong> = Verified Crawler&nbsp;&nbsp;
		</fieldset>
		<textarea name="pike-firewall-logs-print" rows="16" cols="120" readonly><?php echo esc_html($content) ?></textarea>
	</p>
	<p class="submit">
		<input type="submit" name="pike-firewall-analyze-csv" class="button-primary" value="Export to CSV" />
	</p>
	<?php wp_nonce_field('form_submit', 'pike_nonce') ?>
</form>