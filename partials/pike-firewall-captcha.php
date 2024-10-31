<?php
	if ( !defined('ABSPATH') ) die();

	session_start();
	if ( !function_exists('simple_php_captcha') ) {
		require_once PIKEFIREWALL_DIR.'library/captcha/simple-php-captcha.php';
	}
	
	if ( isset($_POST['pike-firewall-submit']) ) {
		if ( !isset($_POST['pike_nonce']) || !wp_verify_nonce(esc_attr($_POST['pike_nonce']), 'form_submit') ) {
			wp_die( __('CSRF detected!') );
		}
		
		$captcha_code = ( isset($_SESSION['pike_captcha_code']) && !empty($_POST['captcha']) ) ? $_SESSION['pike_captcha_code'] : "";
		$captcha = sanitize_text_field(trim($_POST['captcha']));
		
		if ( strlen($captcha_code) > 0 && $captcha === $captcha_code ) {
			if ( !isset($_COOKIE['pike_captcha_valid']) ) {
				setcookie('pike_captcha_valid', TRUE);
			}
			
			$url = 'http'.(isset($_SERVER['HTTPS']) ? 's' : '').'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
			wp_redirect($url);
			exit;
		}
	}
	
	$tmp = simple_php_captcha();
	$_SESSION['pike_captcha_code'] = $tmp['code'];
?>
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Pike Firewall Captcha</title>
		
		<link href='https://fonts.googleapis.com/css?family=Varela' rel='stylesheet' type='text/css'>
		<style>
			body {
				background-color: #f1f1f1;
				font-family: 'Valera', sans-serif;
			}
						
			#captcha-form-box {
				position: fixed; /* or absolute */
			  	top: 50%;
			  	left: 50%;
			  	width: 300px;
			  	height: 200px;
			  	margin-top: -100px;
			  	margin-left: -150px;
			}
			
			#img-thumbnail {
				border: 1px solid #ddd;
				display: block;
			 	margin: auto;
			}
			
			#captcha {
				width: 100%;
				padding: 2px 6px;
			    font-size: 1.3em;
			    outline: 0;
			    border: 1px solid #ddd;
	 			-webkit-box-shadow: inset 0 1px 2px rgba(0,0,0,.07);
				box-shadow: inset 0 1px 2px rgba(0,0,0,.07);
	 			background-color: #fff;
	 			color: #32373c;
	 			outline: 0;
	 			-webkit-transition: .05s border-color ease-in-out;
	 			transition: .05s border-color ease-in-out;
			}
			
			#captcha:focus {
				border-color: #5b9dd9;
			}
			
			#info {
				color: #32373c;
				font-size: 14px;
			}
			
			#submitBtn {
				background: #0091cd;
			    border-color: #0073aa;
			    border-width: 1px;
			    border-style: solid;
			    -webkit-box-shadow: inset 0 1px 0 rgba(120,200,230,.6);
			    box-shadow: inset 0 1px 0 rgba(120,200,230,.6);
			    color: #fff;
			   	display: inline-block;
			    text-decoration: none;
			    font-size: 13px;
			    line-height: 26px;
			    height: 28px;
			    margin: 0;
			    padding: 0 10px 1px;
			    cursor: pointer;
			    -webkit-appearance: none;
			    -webkit-border-radius: 3px;
			    border-radius: 3px;
			    white-space: nowrap;
			    -webkit-box-sizing: border-box;
			    -moz-box-sizing: border-box;
			    box-sizing: border-box;
			}
		</style>
	</head>
	
	<body>
		<div id="captcha-form-box">
			<form name="captcha-form" action="" method="post">
				<img src="<?php echo 'data:image/png;base64,'.esc_html($tmp['image']) ?>" alt="Pike-Firewall-Captcha" id="img-thumbnail" /><br/>
				<input type="text" name="captcha" id="captcha" placeholder="" autocomplete="off" required /><br/>
				<span class="text-navy small info">Are you human?</span><br/><br/>
				<input type="submit" name="pike-firewall-submit" id="submit" value="Submit" />
				<?php wp_nonce_field('form_submit', 'pike_nonce') ?>
			</form>
		</div>
	</body>
</html>