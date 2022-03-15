if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141137" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-06-04 12:33:52 +0700 (Mon, 04 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HID VertX Detection (discoveryd)" );
	script_tag( name: "summary", value: "Detection of HID VertX Access Control Devices.

The script sends a connection request to the server and attempts to detect HID VertX Access Control Devices and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 4050, 4070 );
	script_xref( name: "URL", value: "https://www.hidglobal.com/products/controllers" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 4070, ipproto: "udp" );
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
query = "discover;013;";
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
close( soc );
if(IsMatchRegexp( recv, "^discovered;" )){
	version = "unknown";
	set_kb_item( name: "hid_vertx/detected", value: TRUE );
	data = split( buffer: recv, sep: ";", keep: FALSE );
	for(i = 0;i < max_index( data );i++){
		if(i == 2){
			mac = data[i];
			register_host_detail( name: "MAC", value: mac, desc: "gb_hid_vertx_discoveryd_detect.nasl" );
			replace_kb_item( name: "Host/mac_address", value: mac );
			extra += "\nMAC Address:    " + mac;
		}
		if(i == 3){
			extra += "\nName:           " + data[i];
		}
		if(i == 4){
			extra += "\nInternal IP:    " + data[i];
		}
		if(i == 6){
			model = data[i];
			set_kb_item( name: "hid_vertx/model", value: model );
		}
		if(i == 7){
			version = data[i];
		}
		if(i == 8){
			extra += "\nBuild Date:     " + data[i];
		}
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/h:hid:vertx:" );
	if(!cpe){
		cpe = "cpe:/h:hid:vertx";
	}
	service_register( port: port, proto: "discoveryd", ipproto: "udp" );
	register_product( cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "discoveryd" );
	log_message( data: build_detection_report( app: "HID VertX " + model, version: version, cpe: cpe, extra: extra ), port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

