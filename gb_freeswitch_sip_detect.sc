if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804024" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-10-07 18:21:20 +0530 (Mon, 07 Oct 2013)" );
	script_name( "FreeSWITCH Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of FreeSWITCH over SIP.

  This script performs SIP based detection of FreeSWITCH." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	exit( 0 );
}
require("sip.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(!banner || !ContainsString( banner, "FreeSWITCH" )){
	exit( 0 );
}
set_kb_item( name: "freeswitch/detected", value: TRUE );
set_kb_item( name: "freeswitch/sip/" + proto + "/detected", value: TRUE );
set_kb_item( name: "freeswitch/sip/" + proto + "/port", value: port );
set_kb_item( name: "freeswitch/sip/" + proto + "/" + port + "/concluded", value: banner );
version = "unknown";
switchVer = eregmatch( pattern: "FreeSWITCH-.*/([0-9.]+)", string: banner );
if(!isnull( switchVer[1] )){
	version = switchVer[1];
}
set_kb_item( name: "freeswitch/sip/" + proto + "/" + port + "/version", value: version );
exit( 0 );

