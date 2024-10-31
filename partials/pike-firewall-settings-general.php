<?php if ( !defined('ABSPATH') ) die(); ?>
<form method="post" action="options.php">
	<?php settings_fields('pike_firewall'); ?>  
	<?php do_settings_sections( __FILE__ ); ?>	
	<input type="hidden" name="pike_firewall[stomp_with_me]" value="<?php echo time() ?>" />
	<input type="hidden" name="pike_firewall[version]" value="<?php echo isset($pike_options['version']) ? esc_html($pike_options['version']) : '0.0.1' ?>" />
	<input type="hidden" name="pike_firewall[update_progress]" value="<?php echo isset($pike_options['update_progress']) ? esc_html($pike_options['update_progress']) : 'no' ?>" />
	<input type="hidden" name="pike_firewall[services_update_time]" value="<?php echo isset($pike_options['services_update_time']) ? esc_html($pike_options['services_update_time']) : time() ?>" />
	<input type="hidden" name="pike_firewall[crawlers_update_time]" value="<?php echo isset($pike_options['crawlers_update_time']) ? esc_html($pike_options['crawlers_update_time']) : time() ?>" />
	<p>		
		<label><strong>Update Tor block list:</strong></label><br/>
		<small>Default is free version of the tor exit list service. During beta period is equal to premium.</small><br/>
		<input type="text" name="pike_firewall[default_tor][url]" value="<?php echo isset($pike_options['default_tor']['url']) ? esc_url($pike_options['default_tor']['url']) : '' ?>" size="40" />&nbsp;&nbsp;&nbsp;&nbsp;
		Enable/Disable <input type="checkbox" name="pike_firewall[default_tor][enable]" value="" <?php echo (isset($pike_options['default_tor']['enable'])) ? 'checked' : '' ?> />
	</p>
	<p>		
		<label><strong>Proxy list:</strong></label><br/>
		<small>Default is free version of the proxy list service. During beta period is equal to premium.</small><br/>
		<input type="text" name="pike_firewall[default_proxy][url]" value="<?php echo isset($pike_options['default_proxy']['url']) ? esc_url($pike_options['default_proxy']['url']) : '' ?>" size="40" />&nbsp;&nbsp;&nbsp;&nbsp;
		Enable/Disable <input type="checkbox" name="pike_firewall[default_proxy][enable]" value="" <?php echo (isset($pike_options['default_proxy']['enable'])) ? 'checked' : '' ?> />
	</p>
	<p>		
		<label><strong>Range list:</strong></label><br/>
		<small>Default is free version of the range list service. During beta period is equal to premium.</small><br/>
		<input type="text" name="pike_firewall[default_range][url]" value="<?php echo isset($pike_options['default_range']['url']) ? esc_url($pike_options['default_range']['url']) : '' ?>" size="40" />&nbsp;&nbsp;&nbsp;&nbsp;
		Enable/Disable <input type="checkbox" name="pike_firewall[default_range][enable]" value="" <?php echo (isset($pike_options['default_range']['enable'])) ? 'checked' : '' ?> />
	</p>
	<p>		
		<label><strong>Crawlers list:</strong></label><br/>
		<small>Default is free version of the crawlers list service. During beta period is equal to premium.</small><br/>
		<input type="text" name="pike_firewall[default_crawlers][url]" value="<?php echo isset($pike_options['default_crawlers']['url']) ? esc_url($pike_options['default_crawlers']['url']) : '' ?>" size="40" />&nbsp;&nbsp;&nbsp;&nbsp;
		Enable/Disable <input type="checkbox" name="pike_firewall[default_crawlers][enable]" value="" <?php echo (isset($pike_options['default_crawlers']['enable'])) ? 'checked' : '' ?> />
	</p>
	<p>		
		<label><strong>Data centers:</strong></label><br/>
		<small>Truncated database of data centers ip ranges that allow anonymous services hosting is shipped with plugin installation.<br/>For complete database and realtime updates write at contact[at]hqpeak[dot]com</small><br/>
	</p>
	<p><a href="<?php echo esc_url('http://pike.hqpeak.com/') ?>" target="_blank">Learn more</a> or get <a href="<?php echo esc_url('http://pike.hqpeak.com/account/') ?>" target="_blank">premium service</a> access.</p><br/>
	
	<p>
		<label><strong>Cron Job:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[cron_check]" value="" <?php echo isset($pike_options['cron_check']) ? 'checked' : '' ?> />Enable Cron Job<br/>
		<small>When checked, updates are performed using WP_Cron, if not plugin is taking care reagrding updates</small><br/>
	</p><br/>
	
	<p>
		<label><strong>Filter Humans:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[captcha_check]" value="" <?php echo isset($pike_options['captcha_check']) ? 'checked' : '' ?> />Proove that visitor is a human<br/>
		<small>When enabled, a visitor coming form Anonymous network is required to proove himself as human before proceeding with action</small><br/>
	</p><br/>
	
	<p>
		<label><strong>Requests to allow:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[check][visit]" value="" <?php echo isset($pike_options['check']['visit']) ? 'checked' : '' ?> />Visits&nbsp;&nbsp;
		<small>(Anonymous users can read only public content on the site)</small><br/>
		<input type="checkbox" name="pike_firewall[check][comment]" value="" <?php echo isset($pike_options['check']['comment']) ? 'checked' : '' ?> />Comments&nbsp;&nbsp;
		<small>(Anonymous users can post comments)</small><br/>
		<input type="checkbox" name="pike_firewall[check][registration]" value="" <?php echo isset($pike_options['check']['registration']) ? 'checked' : '' ?> />Registration&nbsp;&nbsp;
		<small>(Anonymous users can register for the site)</small><br/>
		<input type="checkbox" name="pike_firewall[check][subscription]" value="" <?php echo isset($pike_options['check']['subscription']) ? 'checked' : '' ?> />Subscription&nbsp;&nbsp;
		<small>(Anonymous users can subscribe)</small><br/>
		<input type="checkbox" name="pike_firewall[check][administration]" value="" <?php echo isset($pike_options['check']['administration']) ? 'checked' : '' ?> />Administration&nbsp;&nbsp;
		<small>(Anonymous users can access administration panel)</small><br/>
		<input type="checkbox" name="pike_firewall[check][request]" value="" <?php echo isset($pike_options['check']['request']) ? 'checked' : '' ?> />Request&nbsp;&nbsp;
		<small>(Anonymous users can send POST requests)</small><br/>
	</p>
	<p>	
		<label><strong>Requests to deny:</strong></label><br/>
		<small>Here goes all the POST and GET parameters you want to deny [enter them one by one, separated by comma]</small><br/>
		<textarea name="pike_firewall[deny]" rows="8" cols="60"><?php echo isset($pike_options['deny']) ? esc_html($pike_options['deny']) : '' ?></textarea>
	</p><br/>
	
	<p>
		<label><strong>Block fake crawlers:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[crawler_check]" value="" <?php echo isset($pike_options['crawler_check']) ? 'checked' : '' ?> />Block fake crawlers pretending to be Google, Yahoo, Bing, Yandex<br/>
	</p>
	<p>
		<label><strong>Track and analyze verified crawlers:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[crawler_analyze][google]" value="" <?php echo isset($pike_options['crawler_analyze']['google']) ? 'checked' : '' ?> />Google<br/>
		<input type="checkbox" name="pike_firewall[crawler_analyze][yahoo]" value="" <?php echo isset($pike_options['crawler_analyze']['yahoo']) ? 'checked' : '' ?> />Yahoo<br/>
		<input type="checkbox" name="pike_firewall[crawler_analyze][bing]" value="" <?php echo isset($pike_options['crawler_analyze']['bing']) ? 'checked' : '' ?> />Bing<br/>
		<input type="checkbox" name="pike_firewall[crawler_analyze][yandex]" value="" <?php echo isset($pike_options['crawler_analyze']['yandex']) ? 'checked' : '' ?> />Yandex<br/>
		<input type="checkbox" name="pike_firewall[crawler_analyze][facebook]" value="" <?php echo isset($pike_options['crawler_analyze']['facebook']) ? 'checked' : '' ?> />Facebook
	</p><br/>
	
	<p>
		<label><strong>Intrusion Detection:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[intrusion][foreign_origin]" value="" <?php echo isset($pike_options['intrusion']['foreign_origin']) ? 'checked' : '' ?> />POST requests with foreign origin<br/>
		<input type="checkbox" name="pike_firewall[intrusion][blank_useragent]" value="" <?php echo isset($pike_options['intrusion']['blank_useragent']) ? 'checked' : '' ?> />POST requests with blank User Agent<br/>
		<input type="checkbox" name="pike_firewall[intrusion][cmd_useragent]" value="" <?php echo isset($pike_options['intrusion']['cmd_useragent']) ? 'checked' : '' ?> />Requests from Command-Line Browser &amp; Software libraries<br/>
		<input type="checkbox" name="pike_firewall[intrusion][user_enumeration]" value="" <?php echo isset($pike_options['intrusion']['user_enumeration']) ? 'checked' : '' ?> />Wordpress user enumeration<br/>
		<input type="checkbox" name="pike_firewall[intrusion][proxy_headers]" value="" <?php echo isset($pike_options['intrusion']['proxy_headers']) ? 'checked' : '' ?> />Detect Proxy Headers<br/>
	</p><br/>
	
	<p>
		<label><strong>Pike Firewall Login attempts:</strong></label><br />
		<input type="checkbox" name="pike_firewall[login_attempts]" value="" <?php echo isset($pike_options['login_attempts']) ? 'checked' : '' ?>>Enable Login Attempts logging&nbsp;&nbsp;
		<small>(When enabled, all user login attempts are logged in database)</small><br />
	</p><br/>
	
	<p>
		<label><strong>Whitelist IP:</strong></label><br/>
		<small>Here goes all the IP addresses that should be whitelisted, separated by a comma</small><br/>
		<textarea name="pike_firewall[whitelist]" rows="10" cols="70"><?php echo isset($pike_options['whitelist']) ? esc_html($pike_options['whitelist']) : '' ?></textarea>
	</p><br/>
	
	<p>
		<label><strong>Custom Pike Firewall logo message:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[custom_msg][enable]" value="" <?php echo isset($pike_options['custom_msg']['enable']) ? 'checked' : '' ?> />Enable Anonymous logo message&nbsp;&nbsp;
		<small>(When enabled, a custom message with Anonymous logo and ip address of the tor user is displayed)</small><br/><br/>
		<small>Here goes the custom message you want to show to the Anonymous users</small><br/>
		<textarea name="pike_firewall[custom_msg][text]" rows="10" cols="70"><?php echo isset($pike_options['custom_msg']['text']) ? esc_html($pike_options['custom_msg']['text']) : '' ?></textarea>
	</p><br/>
	
	<p>
		<label><strong>Stealth mode logging:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[stealth_mode]" value="" <?php echo isset($pike_options['stealth_mode']) ? 'checked' : '' ?> />Enable Stealth Mode logging&nbsp;&nbsp;
		<small>(When enabled, all anonymous users vistis are logged in database)</small><br/>
	</p><br/>
	
	<p>
		<label><strong>Email &amp; Notifications:</strong></label><br/>
		<small>Choose how do you want to receive the notifications</small><br/>
		<select name="pike_firewall[send_email][type]">
			<option value="email" <?php echo (isset($pike_options['send_email']['type']) && $pike_options['send_email']['type'] == 'email') ? 'selected' : '' ?>>Email</option>
			<!--
			<option value="sms" <?php echo (isset($pike_options['send_email']['type']) && $pike_options['send_email']['type'] == 'sms') ? 'selected' : '' ?>>SMS</option>
			<option value="other" <?php echo (isset($pike_options['send_email']['type']) && $pike_options['send_email']['type'] == 'other') ? 'selected' : '' ?>>Other</option> -->
		</select><br/>
		<!-- <small>Enter your email address or phone number for receiving notifications when something suspicious is detected</small><br/> -->
		<small>Enter your email address for receiving notifications when something suspicious is detected</small><br/>
		<input type="text" name="pike_firewall[send_email][recipient]" value="<?php echo isset($pike_options['send_email']['recipient']) ? esc_html($pike_options['send_email']['recipient']) : '' ?>" placeholder="example@domain.com" size="30" maxlength="50" /><br/><br/>
		<input type="checkbox" name="pike_firewall[send_email][0]" value="" <?php echo isset($pike_options['send_email'][0]) ? 'checked' : '' ?> />Fake Crawlers&nbsp;&nbsp;
		<small>(Send email to admin when fake crawler activity is detected)</small><br/>
		<input type="checkbox" name="pike_firewall[send_email][1]" value="" <?php echo isset($pike_options['send_email'][1]) ? 'checked' : '' ?> />Admin access&nbsp;&nbsp;
		<small>(Send email to admin when Admin Dashboard is entered)</small><br/>
		<input type="checkbox" name="pike_firewall[send_email][2]" value="" <?php echo isset($pike_options['send_email'][2]) ? 'checked' : '' ?> />User Registration&nbsp;&nbsp;
		<small>(Send email to admin on user registration)</small><br/>
		<input type="checkbox" name="pike_firewall[send_email][3]" value="" <?php echo isset($pike_options['send_email'][3]) ? 'checked' : '' ?> />Foreign Origin User-Agent&nbsp;&nbsp;
		<small>(Send email to admin when foreign origin User-Agent is detected)</small><br/>
		<input type="checkbox" name="pike_firewall[send_email][4]" value="" <?php echo isset($pike_options['send_email'][4]) ? 'checked' : '' ?> />cmd Browser / Software library&nbsp;&nbsp;
		<small>(Send email to admin when cmd Browser and/or Software library is used)</small><br/>
		<input type="checkbox" name="pike_firewall[send_email][5]" value="" <?php echo isset($pike_options['send_email'][5]) ? 'checked' : '' ?> />User Enumeration&nbsp;&nbsp;
		<small>(Send email to admin when User Enumeration is detected)</small><br/>
		<input type="checkbox" name="pike_firewall[send_email][6]" value="" <?php echo isset($pike_options['send_email'][6]) ? 'checked' : '' ?> />Failed login attempts&nbsp;&nbsp;
		<small>(Send email to admin when user is failed to login)</small><br/>
	</p><br/>

	<p>
		<label><strong>Apache logs analyzer:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[analyze][crawlers_f]" value="" <?php echo isset($pike_options['analyze']['crawlers_f']) ? 'checked' : '' ?> />Fake Crawlers analyze<br/>
		<input type="checkbox" name="pike_firewall[analyze][crawlers_v]" value="" <?php echo isset($pike_options['analyze']['crawlers_v']) ? 'checked' : '' ?> />Verified Crawlers analyze<br/>
		<input type="checkbox" name="pike_firewall[analyze][tor_proxy]" value="" <?php echo isset($pike_options['analyze']['tor_proxy']) ? 'checked' : '' ?> />Tor/Proxy analyze<br/>
		<input type="checkbox" name="pike_firewall[analyze][datacenters]" value="" <?php echo isset($pike_options['analyze']['datacenters']) ? 'checked' : '' ?> />Datacenters analyze<br/>
	</p><br/>
	
	<p>
		<label><strong>Filesystem scanner:</strong></label><br/>
		<input type="checkbox" name="pike_firewall[file_scan][cron]" value="" <?php echo isset($pike_options['file_scan']['cron']) ? 'checked' : '' ?> />Cron scanner<br/>
		<small>When enabled, the root directory of the WP installation is automatically scanned for changes, as defined below</small><br/><br/>
		<small>Set the time when you want the cron to run the scan for a first time, as well as the time interval of the next scans</small><br/>
		<small>Please note that WP cron uses <strong>UTC/GMT</strong> time, not local time</small><br/>
		<input type="text" name="pike_firewall[file_scan][time]" value="<?php echo isset($pike_options['file_scan']['time']) ? esc_html($pike_options['file_scan']['time']) : '' ?>" placeholder="YYYY/MM/DD hh:mm" size="20" />
		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
		<input type="text" name="pike_firewall[file_scan][interval]" value="<?php echo isset($pike_options['file_scan']['interval']) ? esc_html($pike_options['file_scan']['interval']) : '' ?>" size="20" />
		<select name="pike_firewall[file_scan][interval_unit]" style="margin-top:-5px">
			<option value="sec" <?php echo (isset($pike_options['file_scan']['interval_unit']) && $pike_options['file_scan']['interval_unit'] == 'sec') ? 'selected' : '' ?>>Second(s)</option>
			<option value="min" <?php echo (isset($pike_options['file_scan']['interval_unit']) && $pike_options['file_scan']['interval_unit'] == 'min') ? 'selected' : '' ?>>Minute(s)</option>
			<option value="hours" <?php echo (isset($pike_options['file_scan']['interval_unit']) && $pike_options['file_scan']['interval_unit'] == 'hours') ? 'selected' : '' ?>>Hour(s)</option>
			<option value="days" <?php echo (isset($pike_options['file_scan']['interval_unit']) && $pike_options['file_scan']['interval_unit'] == 'days') ? 'selected' : '' ?>>Day(s)</option>
		</select>
		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
		<input type="button" name="pike-firewall-fs-reset" class="pike-firewall-fs-reset button-secondary button-small" value="Reset cron" data-nonce="<?php echo wp_create_nonce('pike_nonce') ?>" />
		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="fs-reset-msg"></span><br/><br/>
		<small>Here goes all the files and directories that you want ommited from the scan, relative to the root directory, separated by a comma</small><br/>
		<textarea name="pike_firewall[file_scan][directory]" rows="10" cols="70"><?php echo isset($pike_options['file_scan']['directory']) ? esc_html($pike_options['file_scan']['directory']) : '' ?></textarea>
	</p><br/>
	 
	<p class="submit">
		<input type="submit" id="submitBtn" name="pike-firewall-submit" class="button-primary" value="Save Changes" />
	</p>
	<?php wp_nonce_field('form_submit', 'pike_nonce') ?>
</form>