if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11725" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 267 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-1999-1030" );
	script_xref( name: "OSVDB", value: "9826" );
	script_name( "counter.exe vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 John Lampe" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Remove it from the cgi-bin or scripts directory." );
	script_tag( name: "summary", value: "The CGI 'counter.exe' exists on this webserver.
  Some versions of this file are vulnerable to remote exploit." );
	script_tag( name: "impact", value: "An attacker may make use of this file to gain access to
  confidential data or escalate their privileges on the Web server." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/counter.exe";
	if(http_is_cgi_installed_ka( item: url, port: port )){
		req = NASLString( "GET ", dir, "/counter.exe?%0A", "\\r\\n\\r\\n" );
		soc = open_sock_tcp( port );
		if( soc ){
			send( socket: soc, data: req );
			r = http_recv( socket: soc );
			close( soc );
		}
		else {
			exit( 0 );
		}
		soc2 = open_sock_tcp( port );
		if(!soc2){
			security_message( port: port );
			exit( 0 );
		}
		send( socket: soc2, data: req );
		r = http_recv( socket: soc2 );
		if(!r){
			security_message( port: port );
			exit( 0 );
		}
		if(egrep( pattern: ".*Access Violation.*", string: r )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

