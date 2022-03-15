if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108070" );
	script_version( "2020-11-12T13:45:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 13:45:39 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-02-05 13:05:06 +0100 (Sun, 05 Feb 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "TeamSpeak 3 Server Detection (UDP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 9987, 9988, 9989 );
	script_tag( name: "summary", value: "This host is running a TeamSpeak 3 Server. TeamSpeak is proprietary Voice over IP
  software that allows users to speak on a chat channel with other users, much like a telephone conference call." );
	script_xref( name: "URL", value: "http://www.teamspeak.com/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
proto = "udp";
port = unknownservice_get_port( default: 9987, ipproto: proto );
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x54, 0x53, 0x33, 0x49, 0x4e, 0x49, 0x54, 0x31, 0x00, 0x65, 0x00, 0x00, 0x88, 0x07, 0x95, 0x4b, 0x40, 0x00, 0x58, 0x97, 0x09, 0x2d, 0xf7, 0xbb, 0xb2, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: req );
res = recv( socket: soc, length: 64 );
close( soc );
if(!res){
	exit( 0 );
}
len = strlen( res );
if(len != 32 && len != 16){
	exit( 0 );
}
if(ContainsString( res, "TS3INIT1" )){
	version = "unknown";
	cpe = "cpe:/a:teamspeak:teamspeak3";
	install = port + "/" + proto;
	set_kb_item( name: "teamspeak3_server/detected", value: TRUE );
	service_register( port: port, proto: "ts3", ipproto: proto );
	register_product( cpe: cpe, location: install, port: port, proto: proto, service: "ts3" );
	log_message( data: build_detection_report( app: "TeamSpeak 3 Server", version: version, install: install, cpe: cpe ), port: port, proto: proto );
}
exit( 0 );

