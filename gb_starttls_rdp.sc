if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140152" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-02-08 11:18:12 +0100 (Wed, 08 Feb 2017)" );
	script_name( "SSL/TLS: Microsoft Remote Desktop Protocol STARTTLS Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "ms_rdp_detect.sc" );
	script_require_ports( "Services/ms-wbt-server", 3389 );
	script_mandatory_keys( "rdp/detected" );
	script_tag( name: "summary", value: "Checks if the remote Microsoft Remote Desktop Protocol (RDP) service supports the 'PROTOCOL_SSL' flag." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://msdn.microsoft.com/de-de/library/cc240500.aspx" );
	exit( 0 );
}
require("port_service_func.inc.sc");
port = service_get_port( default: 3389, proto: "ms-wbt-server" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 19 );
close( soc );
if(!buf){
	exit( 0 );
}
if(strlen( buf ) != 19){
	exit( 0 );
}
type = ord( buf[11] );
flags = ord( buf[12] );
len = ord( buf[13] ) | ( ord( buf[14] ) << 8 );
sproto = ord( buf[15] ) | ( ord( buf[16] ) << 8 ) | ( ord( buf[17] ) << 16 ) | ( ord( buf[18] ) << 24 );
if(len != 8){
	exit( 0 );
}
if(type == 2 && ( sproto == 1 || sproto == 2 )){
	set_kb_item( name: "msrdp/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "msrdp" );
	log_message( port: port, data: "The remote Microsoft Remote Desktop Protocol (RDP) service supports the 'PROTOCOL_SSL' flag." );
}
exit( 0 );

