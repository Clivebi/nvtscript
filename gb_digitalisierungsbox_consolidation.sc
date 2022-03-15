if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143196" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-11-28 05:48:45 +0000 (Thu, 28 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Digitalisierungsbox Detection Consolidation" );
	script_tag( name: "summary", value: "Reports the Digitalisierungsbox model and version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_digitalisierungsbox_http_detect.sc", "gb_digitalisierungsbox_telnet_detect.sc" );
	script_mandatory_keys( "digitalisierungsbox/detected" );
	script_xref( name: "URL", value: "https://www.telekom.de" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "digitalisierungsbox/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw = "unknown";
for source in make_list( "http",
	 "telnet" ) {
	version_list = get_kb_list( "digitalisierungsbox/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_fw == "unknown"){
			detected_fw = version;
		}
		break;
	}
	model_list = get_kb_list( "digitalisierungsbox/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "digitalisierungsbox/model", value: model );
			break;
		}
	}
}
name = "Digitalisierungsbox ";
if( detected_model != "unknown" ){
	os_name = name + detected_model + " Firmware";
	hw_name = name + detected_model;
	os_cpe = build_cpe( value: detected_fw, exp: "^([0-9.]+)", base: "cpe:/o:telekom:digitalisierungsbox_" + tolower( detected_model ) + "_firmware:" );
	if(!os_cpe){
		cpe = "cpe:/o:telekom:digitalisierungsbox_" + tolower( detected_model ) + "_firmware";
	}
	hw_cpe = "cpe:/h:telekom:digitalisierungsbox_" + tolower( detected_model );
}
else {
	os_name = name + "Unknown Model Firmware";
	hw_name = name + "Unknown Model";
	os_cpe = build_cpe( value: detected_fw, exp: "^([0-9.]+)", base: "cpe:/o:telekom:digitalisierungsbox_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:telekom:digitalisierungsbox_firmware";
	}
	hw_cpe = "cpe:/h:telekom:digitalisierungsbox";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Digitalisierungsbox Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(http_ports = get_kb_list( "digitalisierungsbox/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "digitalisierungsbox/http/" + port + "/concluded" );
		concUrl = get_kb_item( "digitalisierungsbox/http/" + port + "/concludedUrl" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
	}
}
if(telnet_ports = get_kb_list( "digitalisierungsbox/telnet/port" )){
	for port in telnet_ports {
		extra += "Telnet on port " + port + "/tcp\n";
		concluded = get_kb_item( "digitalisierungsbox/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "telnet" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "telnet" );
	}
}
report = build_detection_report( app: os_name, version: detected_fw, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n\n";
	report += extra;
}
log_message( port: 0, data: report );
exit( 0 );

