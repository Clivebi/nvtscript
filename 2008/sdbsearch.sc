if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80084" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-1130" );
	script_name( "sdbsearch.cgi" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Modify the script so that it filters
  the HTTP_REFERRER variable, or delete it." );
	script_tag( name: "summary", value: "The SuSE cgi 'sdbsearch.cgi' is installed.
  This cgi allows a local (and possibly remote) user to execute arbitrary
  commands with the privileges of the HTTP server." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/sdbsearch.cgi?stichwort=anything";
	req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Referer: http://", host, "/../../../../etc\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "htdocs//../../../../etc/keylist.txt" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

