jQuery(document).ready( function() {
	jQuery(".pike-firewall-fs-reset").click( function() {
		var nonce = jQuery(this).attr('data-nonce');
		jQuery('.fs-reset-msg').empty();
		jQuery.ajax({
			type: 'post',
			url: pikefirewallAJAXCronReset.ajaxurl,
			data: { action: 'pike_firewall_ajax_cron_reset', nonce: nonce },
			success: function(response) {
//				console.log(response);
				jQuery('.fs-reset-msg').html(response);
			},
			error: function (err) {
//				console.log(err.responseText);
				jQuery('.fs-reset-msg').html(err.responseText);
			}
		})   
	})
})