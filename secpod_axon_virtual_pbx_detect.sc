if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900983" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Axon Virtual PBX Version Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc", "gb_axon_virtual_pbx_web_detect.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_tag( name: "summary", value: "This script performs SIP based detection of Axon Virtual PBX." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("sip.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && ContainsString( banner, "Axon Virtual PBX" )){
	version = "unknown";
	ver = eregmatch( pattern: "Axon Virtual PBX ([0-9.]+)", string: banner );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	set_kb_item( name: "Axon-Virtual-PBX/installed", value: TRUE );
	set_kb_item( name: "Axon-Virtual-PBX/sip/" + port + "/ver", value: version );
	set_kb_item( name: "Axon-Virtual-PBX/sip/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nch:axon_virtual_pbx:" );
	if(!cpe){
		cpe = "cpe:/a:nch:axon_virtual_pbx";
	}
	location = port + "/" + proto;
	register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
	log_message( data: build_detection_report( app: "Axon Virtual PBX", version: version, install: location, cpe: cpe, concluded: ver[0] ), port: port, proto: proto );
}
exit( 0 );

