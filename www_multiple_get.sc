if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18366" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Several GET locks web server" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "embedded_web_server_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote web server shuts down temporarily or blacklists
  us when it receives several GET HTTP/1.0 requests in a row.

  This might trigger false positive in generic destructive or DoS plugins.

  The scanner enabled some countermeasures, however they might be
  insufficient." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_get_is_marked_embedded( port: port )){
	exit( 0 );
}
if(http_is_dead( port: port, retry: 4 )){
	exit( 0 );
}
host = http_host_name( port: port );
req = NASLString( "GET / HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n" );
max = 12;
for(i = 0;i < max;i++){
	recv = http_send_recv( port: port, data: req );
	if(!recv){
		break;
	}
}
if( i == 0 ){
	}
else {
	if(i < max){
		set_kb_item( name: "www/multiple_get/" + port, value: i );
		log_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

