if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103123" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "EMC Networker Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 7938 );
	script_tag( name: "summary", value: "This host is running EMC Networker, a centralized, automated backup solution." );
	script_xref( name: "URL", value: "http://www.emc.com/products/detail/software/networker.htm" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "EMC Networker Detection";
port = 7938;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x80, 0, 0, 0x38, rand() % 256, rand() % 256, rand() % 256, rand() % 256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0xf3, 0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 32 );
if(strlen( buf ) != 32 || ord( buf[0] ) != 128){
	exit( 0 );
}
if(IsMatchRegexp( hexstr( buf ), "^8000001c" )){
	set_kb_item( name: "emc_networker/port", value: port );
	register_host_detail( name: "App", value: NASLString( "cpe:/a:emc:networker" ), desc: SCRIPT_DESC );
	service_register( port: port, proto: "emc_networker" );
	log_message( port: port );
	exit( 0 );
}
exit( 0 );

