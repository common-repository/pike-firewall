<?php if ( !defined('ABSPATH') ) die(); ?>
<p>		
	<?php 
	echo "<table style='margin-left:30px; width:25%; display:inline-table'>";
	echo "<caption style='text-align:left'><strong><u>Installed Plugins</u></strong></caption>";
	foreach ( $plugins as $key => $plugin ) {
		echo "<tr>";
		if ( in_array($key, $active_plugins) ) {
			echo "<td><i>".esc_html($plugin['Name'])."</i> [<strong>active</strong>]</td>";
		} else {
			echo "<td>".esc_html($plugin['Name'])."</td>";
		}
		echo "</tr>";
	}
	echo "</table>";

	echo "<table style='width:25%; display:inline-table'>";
	echo "<caption style='text-align:left'><strong><u>Installed Themes</u></strong></caption>";
	foreach ( $themes as $theme ) {
		echo "<tr>";
		if ( $theme->Name == $active_theme->Name ) {
			echo "<td><i>".esc_html($theme->Name)."</i> [<strong>active</strong>]</td>";
		} else {
			echo "<td>".esc_html($theme->Name)."</td>";
		}
		echo "</tr>";
	}
	echo "</table>";
	?>
</p>