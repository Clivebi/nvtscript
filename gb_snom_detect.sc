if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105168" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-01-14 11:10:30 +0100 (Wed, 14 Jan 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Snom Detection (SIP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_tag( name: "summary", value: "The script attempts to identify a Snom device via a SIP banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(!banner || !ContainsString( banner, "snom" )){
	exit( 0 );
}
set_kb_item( name: "snom/detected", value: TRUE );
set_kb_item( name: "snom/sip/port", value: port );
set_kb_item( name: "snom/sip/" + port + "/proto", value: proto );
set_kb_item( name: "snom/sip/" + port + "/" + proto + "/concluded", value: banner );
model_version = eregmatch( pattern: "snom([0-9]*)/([^\r\n]+)", string: banner );
if(!isnull( model_version[1] ) && model_version[1] != ""){
	set_kb_item( name: "snom/sip/" + port + "/model", value: model_version[1] );
}
if(!isnull( model_version[2] )){
	set_kb_item( name: "snom/sip/" + port + "/version", value: model_version[2] );
}
exit( 0 );

