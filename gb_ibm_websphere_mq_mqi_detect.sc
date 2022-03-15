if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141712" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-11-23 10:29:03 +0700 (Fri, 23 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM WebSphere MQ Detection (MQI)" );
	script_tag( name: "summary", value: "Detection of IBM WebSphere MQ.

The script sends a MQI request to the server and attempts to detect IBM WebSphere MQ and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 1414, 1415 );
	script_xref( name: "URL", value: "https://www.ibm.com/products/mq" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 1414 );
capabilities = make_list( raw_string( 0x26 ),
	 raw_string( 0x07 ),
	 raw_string( 0x08 ) );
func create_init_packet( socket, capabilities ){
	var socket, capabilities, req, channel_name, qm_name;
	channel_name = "SYSTEM.DEF.SVRCONN  ";
	qm_name = "QM1";
	req = raw_string( 0x54, 0x53, 0x48, 0x20, 0x00, 0x00, 0x01, 0x0c, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x02, 0x00, 0x00, 0xb5, 0x01, 0x00, 0x00, 0x49, 0x44, 0x20, 0x20, 0x0d, capabilities, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0xec, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0xff, 0xc9, 0x9a, 0x3b, channel_name, 0x87, 0x00, 0x5b, 0x01, qm_name + crap( data: " ", length: 45 ), 0x2c, 0x01, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x55, 0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x10, 0x13, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, "MQMM09000000", "MQMID" + crap( data: " ", length: 43 ), 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	return req;
}
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
version = "unknown";
for(i = 0;i < 3;i++){
	packet = create_init_packet( capabilities: capabilities[i] );
	send( socket: sock, data: packet );
	recv = recv( socket: sock, length: 2048 );
	if( !recv && !found ){
		close( sock );
		exit( 0 );
	}
	else {
		if(!recv && found){
			break;
		}
	}
	if(hexstr( substr( recv, 0, 3 ) ) != "54534820"){
		close( sock );
		exit( 0 );
	}
	found = TRUE;
	len = strlen( recv );
	errcode = substr( recv, len - 4 );
	if(hexstr( errcode ) == "02000000" || hexstr( errcode ) == "18000000"){
		continue;
	}
	if(strlen( recv ) > 187){
		qm_name = substr( recv, 76, 123 );
		extra += "QM Name:   " + chomp( qm_name );
		version = "";
		vers = substr( recv, 180, 187 );
		for(i = 0;i < strlen( vers );i += 2){
			if( vers[i] == "0" ) {
				version += vers[i + 1];
			}
			else {
				version += vers[i] + vers[i + 1];
			}
			if(i + 2 < strlen( vers )){
				version += ".";
			}
		}
		break;
	}
}
close( sock );
if(found){
	set_kb_item( name: "ibm_websphere_mq/detected", value: TRUE );
	set_kb_item( name: "ibm_websphere_mq/mqi/port", value: port );
	service_register( port: port, proto: "websphere_mq", message: "A WebSphere MQ service answering to MQI requests seems to be running on this port." );
	log_message( port: port, data: "A WebSphere MQ service answering to MQI requests seems to be running on this port." );
	if(version != "unknown"){
		set_kb_item( name: "ibm_websphere_mq/mqi/" + port + "/version", value: version );
	}
}
exit( 0 );

