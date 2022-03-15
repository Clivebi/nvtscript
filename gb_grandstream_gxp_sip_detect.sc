if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143705" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-04-15 08:08:34 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Grandstream GXP IP Phones Detection (SIP)" );
	script_tag( name: "summary", value: "Detection of Grandstream GXP IP Phones.

  This script performs a SIP based detection of Grandstream GXP IP Phones." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	exit( 0 );
}
require("host_details.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(banner && ContainsString( banner, "Grandstream GXP" )){
	set_kb_item( name: "grandstream/gxp/detected", value: TRUE );
	set_kb_item( name: "grandstream/gxp/sip/port", value: port );
	set_kb_item( name: "grandstream/gxp/sip/" + port + "/proto", value: proto );
	set_kb_item( name: "grandstream/gxp/sip/" + port + "/concluded", value: banner );
	model = "unknown";
	version = "unknown";
	vers = eregmatch( pattern: "(GXP[0-9]+)( ([0-9.]+))?", string: banner );
	if(!isnull( vers[1] )){
		model = vers[1];
	}
	if(!isnull( vers[2] )){
		version = vers[3];
	}
	set_kb_item( name: "grandstream/gxp/sip/" + port + "/model", value: model );
	set_kb_item( name: "grandstream/gxp/sip/" + port + "/version", value: version );
}
exit( 0 );

