if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16313" );
	script_version( "2021-05-18T07:55:59+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 07:55:59 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 12451 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "RaidenHTTPD < 1.1.31 Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "RaidenHTTPD/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "RaidenHTTPD is prone to a remote directory traversal
  vulnerability." );
	script_tag( name: "impact", value: "An attacker exploiting this flaw would be able to gain access to
  potentially confidential material outside of the web root." );
	script_tag( name: "solution", value: "Update to version 1.1.31 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "RaidenHTTP" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for pattern in keys( files ) {
	file = files[pattern];
	if(http_vuln_check( port: port, url: file, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: file );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

