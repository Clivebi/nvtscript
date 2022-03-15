if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106127" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-07-12 10:36:40 +0700 (Tue, 12 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "BACnet Detection" );
	script_tag( name: "summary", value: "A BACnet Service is running at this host.

BACnet is a communications protocol for building automation and control networks." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_require_udp_ports( 47808 );
	script_xref( name: "URL", value: "http://www.bacnet.org/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
func bacnet_query( socket, id ){
	query = raw_string( 0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19 ) + id;
	send( socket: socket, data: query );
	recv = recv( socket: socket, length: 512 );
	if(hexstr( recv[0] ) != 81 || hexstr( recv[6] ) == 50){
		return;
	}
	length = ord( recv[17] );
	if( ( length % 0x10 ) < 5 ) {
		offset = 19;
	}
	else {
		offset = 20;
	}
	return substr( recv, offset, strlen( recv ) - 2 );
}
port = 47808;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
query = raw_string( 0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
if(hexstr( recv[0] ) != 81){
	exit( 0 );
}
set_kb_item( name: "bacnet/detected", value: TRUE );
if( hexstr( recv[6] ) != 50 ){
	if(vendor_name = bacnet_query( socket: soc, id: raw_string( 0x79 ) )){
		set_kb_item( name: "bacnet/vendor", value: vendor_name );
	}
	if(model_name = bacnet_query( socket: soc, id: raw_string( 0x46 ) )){
		set_kb_item( name: "bacnet/model_name", value: model_name );
	}
	if(firmware = bacnet_query( socket: soc, id: raw_string( 0x2c ) )){
		set_kb_item( name: "bacnet/firmware", value: firmware );
	}
	if(appl_sw = bacnet_query( socket: soc, id: raw_string( 0x0c ) )){
		set_kb_item( name: "bacnet/application_sw", value: appl_sw );
	}
	object_name = bacnet_query( socket: soc, id: raw_string( 0x4d ) );
	description = bacnet_query( socket: soc, id: raw_string( 0x1c ) );
	location = bacnet_query( socket: soc, id: raw_string( 0x3a ) );
	service_register( port: port, ipproto: "udp", proto: "bacnet" );
	report = "A BACnet service is running at this port.\n\nThe following information was extracted:\n\n" + "Vendor Name:          " + vendor_name + "\n" + "Model Name:           " + model_name + "\n" + "Firmware:             " + firmware + "\n" + "Application Software: " + appl_sw + "\n" + "Object Name:          " + object_name + "\n" + "Description:          " + description + "\n" + "Location:             " + location + "\n";
	log_message( data: report, port: port, proto: "udp" );
}
else {
	service_register( port: port, ipproto: "udp", proto: "bacnet" );
	log_message( data: "A BACnet service is running at this port.\\n\\nHowever we received the following error\\n" + "BACNet ADPU Type: Error (5)", port: port, porto: "udp" );
	exit( 0 );
}
close( soc );
exit( 0 );

