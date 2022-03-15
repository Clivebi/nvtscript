if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105900" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-03-14 12:14:21 +0700 (Fri, 14 Mar 2014)" );
	script_name( "Speedport DSL-Router Detection (SIP)" );
	script_tag( name: "summary", value: "The script attempts to extract the version number from the SIP banner." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "sip_detection.sc", "sip_detection_tcp.sc" );
	script_mandatory_keys( "sip/banner/available" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("sip.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
infos = sip_get_port_proto( default_port: "5060", default_proto: "udp" );
port = infos["port"];
proto = infos["proto"];
banner = sip_get_banner( port: port, proto: proto );
if(!banner || !ContainsString( banner, "Speedport" )){
	exit( 0 );
}
model = "unknown";
mo = eregmatch( pattern: "Speedport (W ([0-9]+V))", string: banner );
if(!isnull( mo[1] )){
	model = mo[1];
}
fw_version = "unknown";
fw = eregmatch( pattern: "Speedport .* ([0-9]+\\.[0-9]+\\.[0-9]+) \\(", string: banner );
if(!isnull( fw[1] )){
	fw_version = fw[1];
}
if( fw_version == "unknown" && model == "unknown" ){
	set_kb_item( name: "speedport/firmware_version", value: fw_version );
	set_kb_item( name: "speedport/model", value: model );
	cpe_model = str_replace( string: tolower( model ), find: " ", replace: "_" );
}
else {
	cpe_model = "unknown";
}
cpe = build_cpe( value: fw_version, exp: "^([0-9.]+)", base: "cpe:/a:t-com:speedport:" + cpe_model + ":" );
if(!cpe){
	cpe = "cpe:/a:t-com:speedport";
}
location = port + "/" + proto;
register_product( cpe: cpe, port: port, location: location, service: "sip", proto: proto );
log_message( data: build_detection_report( app: "Deutsche Telecom Speedport " + model, version: fw_version, install: location, cpe: cpe, concluded: banner ), port: port, proto: proto );
exit( 0 );

