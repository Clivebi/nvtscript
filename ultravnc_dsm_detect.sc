if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19289" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "UltraVNC w/ DSM plugin detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service1.sc", "vnc.sc" );
	script_require_ports( "Services/unknown", 5900 );
	script_tag( name: "summary", value: "UltraVNC seems to be running on the remote port.

Upon connection, the remote service on this port always sends
the same 12 pseudo-random bytes.

It is probably UltraVNC with the DSM encryption plugin.
This plugin tunnels the RFB protocol into a RC4 encrypted
stream." );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("global_settings.inc.sc");
require("dump.inc.sc");
port = unknownservice_get_port( default: 5900 );
b = get_kb_item( "FindService/tcp/" + port + "/spontaneous" );
if(!COMMAND_LINE && strlen( b ) != 12){
	exit( 0 );
}
s = open_sock_tcp( port );
if(!s){
	exit( 0 );
}
r1 = recv( socket: s, length: 512 );
send( socket: s, data: "012345678901" );
r = recv( socket: s, length: 512 );
close( s );
if(debug_level > 0){
	t = strcat( "Data received on ", get_host_ip(), ":", port );
	dump( ddata: r1, dtitle: t );
	dump( ddata: r, dtitle: t );
}
if(strlen( r1 ) != 12){
	exit( 0 );
}
if(ereg( string: r1, pattern: "^RFB +[0-9]+\\.[0-9]+\n$", icase: 0, multiline: 1 )){
	log_print( "Clear text VNC banner on port ", port, "\n" );
	service_register( port: port, proto: "vnc" );
	exit( 0 );
}
if(strlen( r ) > 0){
	exit( 0 );
}
s = open_sock_tcp( port );
if(!s){
	exit( 0 );
}
r2 = recv( socket: s, length: 512 );
if(r2 != r1){
	exit( 0 );
}
send( socket: s, data: r2 );
r = recv( socket: s, length: 512 );
close( s );
if(debug_level > 0){
	dump( ddata: r2, dtitle: t );
	dump( ddata: r, dtitle: t );
}
if(strlen( r ) == 0){
	exit( 0 );
}
total = 0;
all_ascii = TRUE;
for(i = 0;i < 12;i++){
	z = ord( r[i] );
	if(z < 9 || z > 126){
		all_ascii = 0;
	}
	for(j = 1;j < 256;j *= 2){
		if(z & j){
			total++;
		}
	}
}
debug_print( "port=", port, "- all_ascii=", all_ascii, " - total=", total, "\n" );
if(all_ascii){
	debug_print( "Banner is in ASCII characters\n" );
}
if(total >= 24 && total <= 72){
	log_message( port: port );
	service_register( port: port, proto: "ultravnc-dsm" );
}

