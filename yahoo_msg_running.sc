if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102001" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:34:11 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Yahoo Messenger Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 5101 );
	script_xref( name: "URL", value: "http://libyahoo2.sourceforge.net/ymsg-9.txt" );
	script_xref( name: "URL", value: "http://www.astahost.com/info.php/yahoo-protocol-part-10-peer-peer-transfers_t11490.html" );
	script_xref( name: "URL", value: "http://libyahoo2.sourceforge.net/README" );
	script_xref( name: "URL", value: "http://www.ycoderscookbook.com/" );
	script_xref( name: "URL", value: "http://www.venkydude.com/articles/yahoo.htm" );
	script_tag( name: "summary", value: "Yahoo Messenger is running on this machine and this port. It can
  be used to share files and chat with other users." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
ymsg = NASLString( "YMSG" );
version = raw_string( 0x00, 0x10, 0x00, 0x00 );
pkt_len = raw_string( 0x00, 0x00 );
service = raw_string( 0x00, 0x4d );
status = raw_string( 0x00, 0x00, 0x00, 0x00 );
session_id = raw_string( 0x00, 0x00, 0x00, 0x00 );
separator = raw_string( 0xc0, 0x80 );
crap_len = 512;
first_key_value_pair = NASLString( "4" + separator + "bladyjoker" + separator );
second_key_value_pair = NASLString( "241" + separator + "0" + separator );
third_key_value_pair = NASLString( "5" + separator + "bladyjoker" + separator );
fourth_key_value_pair = NASLString( "13" + separator + "5" + separator );
fifth_key_value_pair = NASLString( "49" + separator + "PEERTOPEER" + separator );
data = first_key_value_pair + second_key_value_pair + third_key_value_pair + fourth_key_value_pair + fifth_key_value_pair;
pkt_len = raw_string( 0x00, 0x3D );
yahoo_pkt = ymsg + version + pkt_len + service + status + session_id + data;
yahoo_pkt_len = strlen( yahoo_pkt );
port = unknownservice_get_port( default: 5101 );
sock = open_sock_tcp( port );
if(sock){
	send( socket: sock, data: yahoo_pkt, length: yahoo_pkt_len );
	recv_buffer = recv( socket: sock, length: 256 );
	close( sock );
	if(ContainsString( recv_buffer, "YMSG" )){
		set_kb_item( name: "yahoo_messenger/installed", value: TRUE );
		service_register( port: port, proto: "yahoo_messenger" );
		log_message( port: port );
	}
}
exit( 0 );

