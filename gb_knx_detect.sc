if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142147" );
	script_version( "2021-04-14T12:07:16+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 12:07:16 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-03-22 07:54:13 +0100 (Fri, 22 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "KNX Service Detection (UDP)" );
	script_tag( name: "summary", value: "UDP based detection of a KNX service." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 3671 );
	script_xref( name: "URL", value: "https://www.knx.org/" );
	exit( 0 );
}
require("dump.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = unknownservice_get_port( default: 3671, ipproto: "udp" );
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
data = raw_string( 0x06, 0x10, 0x02, 0x03, 0x00, 0x0e, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: data );
recv = recv( socket: soc, length: 1024 );
close( soc );
if(!recv || strlen( recv ) < 60 || hexstr( substr( recv, 2, 3 ) ) != "0204"){
	exit( 0 );
}
knx_addr = substr( recv, 10, 11 );
knx_addr = ( ord( knx_addr[0] ) >> 4 ) + "." + ( ord( knx_addr[0] ) & 0x0f ) + "." + ord( knx_addr[1] );
dev_snum = hexstr( substr( recv, 14, 19 ) );
mcast_addr = substr( recv, 20, 23 );
mcast_addr = ord( mcast_addr[0] ) + "." + ord( mcast_addr[1] ) + "." + ord( mcast_addr[2] ) + "." + ord( mcast_addr[3] );
mac = substr( recv, 24, 29 );
mac = hexstr( mac[0] ) + ":" + hexstr( mac[1] ) + ":" + hexstr( mac[2] ) + ":" + hexstr( mac[3] ) + ":" + hexstr( mac[4] ) + ":" + hexstr( mac[5] );
register_host_detail( name: "MAC", value: mac, desc: "KNX Service Detection" );
replace_kb_item( name: "Host/mac_address", value: mac );
name = substr( recv, 30, 60 );
name = bin2string( ddata: name, noprint_replacement: "" );
if(name){
	set_kb_item( name: "knx/" + port + "/friendlyName", value: name );
	set_kb_item( name: "knx/friendlyName/available", value: TRUE );
}
service_register( port: port, ipproto: "udp", proto: "knx" );
report = "A KNX service is running at this port.\n\nThe following information was extracted:\n\n" + "Device Friendly Name: " + name + "\n" + "MAC Address:          " + mac + "\n" + "KNX Bus Address:      " + knx_addr + "\n" + "Multicast Address:    " + mcast_addr + "\n" + "Device Serial:        " + dev_snum;
log_message( port: port, data: report, proto: "udp" );
exit( 0 );

