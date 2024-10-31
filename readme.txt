=== Pike Firewall ===
Contributors: hqpeak
Donate link: http://hqpeak.com/
Tags: spam, security, tor, firewall, geoip, vpn, cloud, hosting, bots, proxy, attack, malware, ransomware, google, bing, yandex, yahoo, crawlers, fake crawlers, robots, marketing
Requires at least: 3.8.1
Tested up to: 4.7.1
Stable tag: 1.4.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Pike FIrewall stands for limiting actions to the users that came from anonymous traffic sources, IDS for wordpress and robots verification/monitoring. 
 
== Description ==

Most of the time anonymous traffic sources are used to enumerate vulnerabilities of our online product, to perform attack or to be used as a spam source.
This plugin allow us to limit the actions that coud be performed by the users that are coming from this sources using http://pike.hqpeak.com free services.
Could be upgraded to premium or could be set up any url to service that will give you response in the described json format. 
Premium list is updated on real time, free on 2+ hours (during BETA service period is the same as premium) and has its own caching mechanism so isn't affect the speed of the WP instance.
In case you need the realtime blocking service and detailed offline database created with data mining on the past service results feel free to contact us at contact [at] hqpeak [d0t] com 

With this plugin you can apply following constraints to this type of traffic:

- Filter human from bots visits displaying captcha to verify
- Visits   (Can acess public content on the site)
- Comments   (Can post comments)
- Registration   (Can register for the site)
- Subscription   (Can subscribe)
- Administration   (Can access administration panel - do not tick this one :) )
- Request   (Can send POST requests)
- Ban any action on the WP instance based on name/key of the request

Intrusion Detection

We introduce our IDS for wordpress with this release. You can do the following:

- Block POST requests without set up User Agent or User Agent that is popular development library ( used for crawling websites ) e.g. web crawlers 
- Block POST requests originating from another domain (CSRF)
- Stop user enumeration
- Identify proxy traffic via HTTP headers

File integrity check!

Crawlers verification and monitoring

- make sure ( google, yahoo, bing and yandex ) crawlers are never blocked even if you add some extra ranges for blocking
- block fake crawlers that pretend to be valid one
- monitor crawler activity to better understand popular crawlers behaviour and use it to get better SEO results
  
== Installation ==

1. Extract `PikeFirewall`  archive to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Access the administration area Dashboard -> Pike Firewall


== Frequently Asked Questions ==

= What if I have problems activating the plugin? =
For any problem you face with the plugin activation, please visit support forums or contact us at contact@hqpeak.com.

= Does this plugin work with newest version of WordPress and also with older versions? =
Yes, this plugin works really fine with WordPress 3.8.1!
It should also work with earlier versions, but the testing was done at the latest stable version and that is 3.8.1,
so you always should run the latest WordPress version to escape possible problems.

= Do I have to set up the settings every time I activate the plugin? =
Yes. Every time the plugin is activated its options are set to default values, so it means you have to set them up again.

= How many request parameters can I put in the textarea to limit the user by request? =
No limit at all. You can put as many parameters in the textarea as you want. The plugin will recognize any request parameter in the URL
and stop the user immediately.

= What is allowed to the anonymous users by default? =
By default, anonymous users are allowed just to visit the site and read its public content. As you might guess, you can deny this too,
so the anonymous user is stopped before reaching your site. 


== Screenshots ==

1. Pike Firewall settings panel at its default state
2. Pike Firewall settings panel at its default state
3. Pike Firewall settings panel at its default state
4. Pike Firewall logs
5. Pike Firewall blocked request


== Changelog ==
= 1.4.1 =
Bug fix: ip2long passed towards gethostbyaddr
= 1.4 =
New features and new UI
= 1.3.3 =
Bugfix: Fixed data updating 
= 1.3.2 = 
Feature: white list ip addresses
Improvement: Prevent inserting not matching ip patterns ( ipv6 in our case )
= 1.3.1 = 
Fix: doesn't block own ip + tor browser captcha
= 1.2.3 =
Fake crawlers monitoring fix and error page improvement. Added index.php files for omitting directory listing.
= 1.3.0 =
Added apache access logs analyzer with Export to csv functionality. Added file system changes changes scanner and log functionality.
= 1.2.2 =
Facebook crawlers monitoring/whitelist and http clients filtering used by automated scripts
= 1.2.1 =
Checkboxes that let you choose which rules to include/use for blocking / monitoring ( Tor, Proxy, Datacenters )
= 1.2 = 
Google, yahoo, bing and yandex crawlers verification, logging their behaviour and blocking fake crawlers pretending to be valid.
= 1.1 =
Announced Intrusion Detection for WP with its first features
Extended user agent blocking list
= 1.0 =
This is the initial released version.


== Upgrade Notice ==
= 1.4.1 =
Bug fix: ip2long passed towards gethostbyaddr
= 1.4 =
New features and new UI
= 1.3.3 =
Bugfix: Fixed data updating 
= 1.3.2 = 
Feature: white list ip addresses
Improvement: Prevent inserting not matching ip patterns ( ipv6 in our case )
= 1.3.1 = 
Fix: doesn't block own ip + tor browser captcha
= 1.3.0 =
Added apache access logs analyzer with Export to csv functionality. Added file system changes changes scanner and log functionality.
= 1.2.3 =
Fake crawlers monitoring fix and error page improvement. Added index.php files for omitting directory listing.
= 1.2.2 =
Facebook crawlers monitoring/whitelist and http clients filtering used by automated scripts
= 1.2.1 =
Checkboxes that let you choose which rules to include/use for blocking / monitoring ( Tor, Proxy, Datacenters )
= 1.2 =
Crawlers support and extending IDS 
= 1.1 =
No database or permissions changes will be required
= 1.0 =
Just released in public.

