if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108707" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-01-31 09:47:18 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LANCOM Device Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of LANCOM devices.

  This script performs SIP based detection of LANCOM devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	exit( 0 );
}
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "LANCOM " )){
	set_kb_item( name: "lancom/detected", value: TRUE );
	set_kb_item( name: "lancom/sip/" + proto + "/detected", value: TRUE );
	set_kb_item( name: "lancom/sip/" + proto + "/port", value: port );
	set_kb_item( name: "lancom/sip/" + proto + "/" + port + "/detected", value: TRUE );
	version = "unknown";
	model = "unknown";
	infos = eregmatch( pattern: "LANCOM ([^ ]+)([A-Za-z0-9()/ +-]+|[A-Za-z0-9()/ +-.]+\\))? ([0-9]+\\.[0-9.]+)", string: banner );
	if(!isnull( infos[1] )){
		model = infos[1];
	}
	if(!isnull( infos[3] )){
		version = infos[3];
	}
	set_kb_item( name: "lancom/sip/" + proto + "/" + port + "/model", value: model );
	set_kb_item( name: "lancom/sip/" + proto + "/" + port + "/version", value: version );
	if(infos[0]){
		set_kb_item( name: "lancom/sip/" + proto + "/" + port + "/concluded", value: infos[0] );
	}
}
exit( 0 );

