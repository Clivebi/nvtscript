if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140085" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 14:02:18 +0100 (Thu, 01 Dec 2016)" );
	script_name( "Cisco ATA Detection (SIP)" );
	script_tag( name: "summary", value: "SIP based detection of Cisco Analog Telephone Adapter (ATA) devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("sip.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(!banner || !IsMatchRegexp( banner, "^Cisco[- ]ATA ?[0-9]{3}" )){
	exit( 0 );
}
set_kb_item( name: "cisco/ata/detected", value: TRUE );
set_kb_item( name: "cisco/ata/sip/detected", value: TRUE );
set_kb_item( name: "cisco/ata/sip/port", value: port );
set_kb_item( name: "cisco/ata/sip/" + port + "/proto", value: proto );
set_kb_item( name: "cisco/ata/sip/" + port + "/concluded", value: banner );
version = "unknown";
model = "unknown";
mod = eregmatch( pattern: "Cisco[- ]ATA ?([0-9]{3})", string: banner );
if(!isnull( mod[1] )){
	model = mod[1];
}
vers = eregmatch( pattern: "Cisco[^v/]+[/v]([0-9A-Z.-]+)", string: banner );
if(!isnull( vers[1] )){
	version = str_replace( string: vers[1], find: "-", replace: "." );
}
set_kb_item( name: "cisco/ata/sip/" + port + "/model", value: model );
set_kb_item( name: "cisco/ata/sip/" + port + "/version", value: version );
exit( 0 );

