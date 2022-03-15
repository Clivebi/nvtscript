if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.200004" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2005-3514" );
	script_bugtraq_id( 15149 );
	script_name( "Chipmunk Forum <= 1.3 Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "impact", value: "A vulnerability was identified in Chipmunk Forum version 1.3 and prior, which may be exploited by
  remote attackers to execute script code by the user's browser." );
	script_tag( name: "summary", value: "The remote host appears to be running Chipmunk Forum that is vulnerable to cross-site
  scripting attacks." );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2005/2172" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("url_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
xss = "'</a><IFRAME SRC=javascript:alert(%27XSS%20DETECTED%20BY%20VTTEST%27)></IFRAME>";
exss = urlencode( str: xss );
for dir in nasl_make_list_unique( "/chipmunk", "/board", "/forum", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(!res){
		continue;
	}
	if(egrep( pattern: ">Powered by © <A href=[^>]+>Chipmunk Board<", string: res )){
		url = NASLString( dir, "/index.php?forumID=", exss );
		req = http_get( item: url, port: port );
		recv = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!recv){
			continue;
		}
		if(ContainsString( recv, xss )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

