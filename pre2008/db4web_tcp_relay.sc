if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11180" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "DB4Web TCP relay" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Replace the debug page with a non verbose error page." );
	script_tag( name: "summary", value: "DB4Web debug page allows anybody to scan other machines.

  You may be held for responsible." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
testhost = this_host_name();
url = NASLString( "/DB4Web/", testhost, ":23/test" );
r = http_get( port: port, item: url );
c = http_keepalive_send_recv( port: port, data: r );
if(( ContainsString( c, "connect() ok" ) || ContainsString( c, "connect() failed:" ) ) && ContainsString( c, "callmethodbinary_2 failed" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

