if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10407" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "X Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2005 John Jackson" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009 );
	script_tag( name: "summary", value: "This plugin detects X Window servers.

  X11 is a client - server protocol. Basically, the server is in charge of the
  screen, and the clients connect to it and send several requests like drawing
  a window or a menu, and the server sends events back to the clients, such as
  mouse clicks, key strokes, and so on...

  An improperly configured X server will accept connections from clients from
  anywhere. This allows an attacker to make a client connect to the X server to
  record the keystrokes of the user, which may contain sensitive information,
  such as account passwords.
  This can be prevented by using xauth, MIT cookies, or preventing
  the X server from listening on TCP (a Unix sock is used for local
  connections)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
func riptext( data, begin, length ){
	var data, begin, length, count, end, text;
	count = begin;
	end = begin + length - 1;
	if(end >= strlen( data )){
		end = strlen( data ) - 1;
	}
	text = "";
	for(count = begin;count <= end;count++){
		text = NASLString( text + data[count] );
	}
	return text;
}
xwininfo = raw_string( 108, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0 );
for(port = 6000;port < 6010;port++){
	if(!get_port_state( port )){
		continue;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	extra = "";
	send( socket: soc, data: xwininfo );
	res = recv( socket: soc, length: 32 );
	close( soc );
	if(res && strlen( res ) >= 8){
		result = ord( res[0] );
		if(result == 0){
			major = ord( res[2] ) + 256 * ord( res[3] );
			minor = ord( res[4] ) + 256 * ord( res[5] );
			ver = strcat( major, ".", minor );
			set_kb_item( name: "X11/" + port + "/version", value: ver );
			textres = riptext( data: res, begin: 8, length: ord( res[1] ) );
			if(textres){
				set_kb_item( name: "X11/" + port + "/answer", value: textres );
				extra = "Server answered with: " + textres;
			}
			set_kb_item( name: "X11/" + port + "/open", value: FALSE );
			service_register( port: port, proto: "X11" );
			register_and_report_cpe( app: "X Windows Server", ver: ver, base: "cpe:/a:x.org:x11:", expr: "^([0-9.]+([a-z0-9]+)?)", regPort: port, insloc: port + "/tcp", extra: "Server answered with: " + textres );
		}
		if(result == 1){
			major = ord( res[2] ) + 256 * ord( res[3] );
			minor = ord( res[4] ) + 256 * ord( res[5] );
			ver = strcat( major, ".", minor );
			set_kb_item( name: "X11/" + port + "/version", value: ver );
			textres = riptext( data: res, begin: 40, length: ord( res[24] ) );
			if(textres){
				set_kb_item( name: "X11/" + port + "/answer", value: textres );
				extra = "Server answered with: " + textres;
			}
			set_kb_item( name: "X11/" + port + "/open", value: TRUE );
			set_kb_item( name: "X11/open", value: TRUE );
			service_register( port: port, proto: "X11" );
			register_and_report_cpe( app: "X Windows Server", ver: ver, base: "cpe:/a:x.org:x11:", expr: "^([0-9.]+([a-z0-9]+)?)", regPort: port, insloc: port + "/tcp", extra: extra );
		}
		if(result == 2){
			textres = riptext( data: res, begin: 8, length: ord( res[1] ) );
			if(textres){
				set_kb_item( name: "X11/" + port + "/answer", value: textres );
				extra = "Server answered with: " + textres;
			}
			set_kb_item( name: "X11/" + port + "/open", value: FALSE );
			service_register( port: port, proto: "X11" );
			register_and_report_cpe( app: "X Windows Server", cpename: "cpe:/a:x.org:x11", regPort: port, insloc: port + "/tcp", extra: extra );
		}
	}
}
exit( 0 );

