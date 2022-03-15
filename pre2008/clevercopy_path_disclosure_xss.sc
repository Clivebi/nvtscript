if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19392" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_cve_id( "CVE-2005-2326" );
	script_bugtraq_id( 14278, 14395, 14397 );
	script_xref( name: "OSVDB", value: "17919" );
	script_xref( name: "OSVDB", value: "18349" );
	script_xref( name: "OSVDB", value: "18350" );
	script_xref( name: "OSVDB", value: "18351" );
	script_xref( name: "OSVDB", value: "18352" );
	script_xref( name: "OSVDB", value: "18353" );
	script_xref( name: "OSVDB", value: "18354" );
	script_xref( name: "OSVDB", value: "18355" );
	script_xref( name: "OSVDB", value: "18356" );
	script_xref( name: "OSVDB", value: "18357" );
	script_xref( name: "OSVDB", value: "18358" );
	script_xref( name: "OSVDB", value: "18359" );
	script_xref( name: "OSVDB", value: "18360" );
	script_xref( name: "OSVDB", value: "18361" );
	script_xref( name: "OSVDB", value: "18509" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Multiple vulnerabilities in Clever Copy" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2005/07/clever-copy-calendarphp-yr-variable.html" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2005/07/clever-copy-path-disclosure-and-xss.html" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2005/07/clever-copy-unauthorized-read-delete.html" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote version of Clever Copy contains multiple vulnerabilities
  that can lead to path disclosure, cross-site scripting and unauthorized access to private messages" );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
	url = NASLString( dir, "/results.php?", "searchtype=\">", exss, "category&searchterm=", vtstrings["default"] );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, xss )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

