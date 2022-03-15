if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108524" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-12-28 20:35:26 +0100 (Fri, 28 Dec 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Logitech SqueezeCenter/Media Server Detection (SlimProto TCP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/wrapped", 3483 );
	script_tag( name: "summary", value: "Detection of a Logitech SqueezeCenter/Media Server via SlimProto TCP.

  This script sends a SlimProto TCP 'HELLO' request to the target and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("byte_func.inc.sc");
port = service_get_port( default: 3483, proto: "wrapped" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x06 );
req += raw_string( 0x01 );
req += "00:00:00:00:00:00";
req = "HELO" + mkdword( strlen( req ) ) + req;
send( socket: soc, data: req );
res = recv( socket: soc, length: 2, min: 2 );
if(!res || strlen( res ) != 2){
	close( soc );
	exit( 0 );
}
len = getword( blob: res, pos: 0 );
res = recv( socket: soc, length: len, min: len );
if(!res || strlen( res ) != len){
	exit( 0 );
	close( soc );
}
if(IsMatchRegexp( res, "^vers[0-9.]+" )){
	version = "unknown";
	vers = eregmatch( string: res, pattern: "^vers([0-9.]+)", icase: FALSE );
	if(vers[1]){
		version = vers[1];
		set_kb_item( name: "logitech/squeezecenter/tcp/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "logitech/squeezecenter/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/tcp/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/tcp/port", value: port );
	set_kb_item( name: "logitech/squeezecenter/tcp/" + port + "/detected", value: TRUE );
	set_kb_item( name: "logitech/squeezecenter/tcp/" + port + "/version", value: version );
	log_message( port: port, data: "A Logitech SqueezeCenter/Media server supporting the SlimProto protocol seems to be running on this port." );
	service_register( port: port, proto: "squeezecenter", ipproto: "tcp" );
	req = raw_string( 0x00 );
	req = "BYE!" + mkdword( strlen( req ) ) + req;
	send( socket: soc, data: req );
}
close( soc );
exit( 0 );

