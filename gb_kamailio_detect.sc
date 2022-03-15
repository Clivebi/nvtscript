if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105591" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-03-31 14:38:23 +0200 (Thu, 31 Mar 2016)" );
	script_name( "Kamailio Detection (SIP)" );
	script_tag( name: "summary", value: "This scripts try to detect a Kamailio SIP server from the SIP banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(!banner = sip_get_banner( port: port, proto: proto )){
	exit( 0 );
}
if(!ContainsString( banner, "kamailio" )){
	exit( 0 );
}
vers = "unknown";
cpe = "cpe:/a:kamailio:kamailio";
set_kb_item( name: "kamailio/installed", value: TRUE );
version = eregmatch( pattern: "kamailio \\(([^ )]+) ", string: banner );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "kamailio/version", value: vers );
}
location = port + "/" + proto;
register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
log_message( data: build_detection_report( app: "kamailio", version: vers, install: location, cpe: cpe, concluded: banner ), port: port, proto: proto );
exit( 0 );

