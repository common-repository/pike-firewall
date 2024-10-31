<?php if ( !defined('ABSPATH') ) die(); ?>
<p>		
	<label><strong>Filesystem Scanner</strong></label><br/>
	<label>Scan the root directory for file changes:</label><br/>
</p>
<p class="last-scan"></p>
<p class="submit">
	<input type="button" name="pike-firewall-file-scan" class="pike-firewall-file-scan button-primary" value="Scan" data-nonce="<?php echo wp_create_nonce('pike_nonce') ?>" />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="loading"></span>
</p>
<p class="scan-results"></p>