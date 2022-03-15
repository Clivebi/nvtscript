if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18259" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-1612", "CVE-2005-1613" );
	script_bugtraq_id( 13624, 13625 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "OpenBB XSS and SQL injection flaws" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to version 1.0.9 of this software or newer." );
	script_tag( name: "summary", value: "The remote version of OpenBB is vulnerable to cross-site scripting
  attacks, and SQL injection flaws." );
	script_tag( name: "impact", value: "Using a specially crafted URL, an attacker may execute arbitrary commands
  against the remote SQL database or use the remote server to set up a cross site scripting attack." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(ereg( pattern: "Powered by <a href=\"http://www.openbb.com/\" target=\"_blank\">Open Bulletin Board</a>[^0-9]*1\\.(0[^0-9]|0\\.[0-8][^0-9])<br>", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

