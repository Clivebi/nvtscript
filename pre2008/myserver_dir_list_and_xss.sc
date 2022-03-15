if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18218" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2005-1658", "CVE-2005-1659" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 13579, 13578 );
	script_name( "myServer Directory Listing and XSS flaws" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to version 0.8.1 when available" );
	script_tag( name: "summary", value: "The remote host is running myServer, an open-source http server.
  This version is vulnerable to a directory listing flaw and XSS.

  An attacker can execute a cross site scripting attack,
  or gain knowledge of certain system information of the
  server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "50" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<title>MyServer</title>" )){
		url = NASLString( dir, "/.../.../\"onmouseover=\"<script>foo</script>\"" );
		if(http_vuln_check( port: port, url: url, pattern: "<script>foo</script>", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

