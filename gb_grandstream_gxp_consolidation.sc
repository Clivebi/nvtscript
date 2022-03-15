if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143704" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-04-15 07:47:28 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Grandstream GXP IP Phones Detection Consolidation" );
	script_tag( name: "summary", value: "Reports the Grandstream GXP model and version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_grandstream_gxp_http_detect.sc", "gb_grandstream_gxp_sip_detect.sc", "gb_grandstream_gxp_telnet_detect.sc" );
	script_mandatory_keys( "grandstream/gxp/detected" );
	script_xref( name: "URL", value: "http://www.grandstream.com/products/ip-voice-telephony" );
	exit( 0 );
}
if(!get_kb_item( "grandstream/gxp/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_model = "unknown";
detected_version = "unknown";
location = "/";
for source in make_list( "http",
	 "sip",
	 "telnet" ) {
	model_list = get_kb_list( "grandstream/gxp/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			break;
		}
	}
	version_list = get_kb_list( "grandstream/gxp/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
os_name = "Grandstream ";
hw_name = os_name;
if( detected_model != "unknown" ){
	os_name += detected_model + " Firmware";
	hw_name += detected_model;
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:grandstream:" + tolower( model ) + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:grandstream:" + tolower( model ) + "_firmware";
	}
	hw_cpe = "cpe:/h:grandstream:" + tolower( model );
}
else {
	os_name += "GXP Unknown Model Firmware";
	hw_name += "GXP Unknown Model";
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:grandstream:gxp_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:grandstream:gxp_firmware";
	}
	hw_cpe = "cpe:/h:grandstream:gxp";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Grandstream GXP IP Phones Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "grandstream/gxp/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "grandstream/gxp/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
	}
}
if(sip_ports = get_kb_list( "grandstream/gxp/sip/port" )){
	for port in sip_ports {
		proto = get_kb_item( "grandstream/gxp/sip/" + port + "/proto" );
		extra += "SIP on port " + port + "/" + proto + "\n";
		concluded = get_kb_item( "grandstream/gxp/sip/" + port + "/concluded" );
		if(concluded){
			extra += "  SIP Banner: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "sip", proto: proto );
		register_product( cpe: os_cpe, location: location, port: port, service: "sip", proto: proto );
	}
}
if(telnet_ports = get_kb_list( "grandstream/gxp/telnet/port" )){
	for port in telnet_ports {
		extra += "Telnet on port " + port + "/tcp\n";
		concluded = get_kb_item( "grandstream/gxp/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "telnet" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "telnet" );
	}
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );
