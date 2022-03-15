if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140631" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cambium Networks cnPilot Detection Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected Cambium Networks cnPilot including the
  version number and exposed services." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_cambium_cnpilot_http_detect.sc", "gb_cambium_cnpilot_snmp_detect.sc" );
	script_mandatory_keys( "cambium_cnpilot/detected" );
	script_xref( name: "URL", value: "https://www.cambiumnetworks.com/products/wifi/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "cambium_cnpilot/detected" )){
	exit( 0 );
}
detected_fw_version = "unknown";
detected_model = "unknown";
location = "/";
hw_name = "Cambium Networks cnPilot";
for source in make_list( "http",
	 "snmp" ) {
	fw_version_list = get_kb_list( "cambium_cnpilot/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version && detected_fw_version == "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "cambium_cnpilot/fw_version", value: fw_version );
		}
	}
	model_list = get_kb_list( "cambium_cnpilot/" + source + "/*/model" );
	for model in model_list {
		if(model && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "cambium_cnpilot/model", value: model );
		}
	}
}
if( detected_model != "unknown" ){
	os_name = hw_name + " " + detected_model + " Firmware";
	hw_name += " " + detected_model;
	os_cpe = build_cpe( value: tolower( detected_fw_version ), exp: "^([0-9r.-]+)", base: "cpe:/o:cambiumnetworks:cnpilot_" + tolower( detected_model ) + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:cambiumnetworks:cnpilot_" + tolower( detected_model ) + "_firmware";
	}
	hw_cpe = "cpe:/h:cambiumnetworks:cnpilot_" + tolower( detected_model );
}
else {
	os_name = hw_name + " Unknown Model Firmware";
	hw_name += " Unknown Model";
	os_cpe = build_cpe( value: tolower( detected_fw_version ), exp: "^([0-9r.-]+)", base: "cpe:/o:cambiumnetworks:cnpilot_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:cambiumnetworks:cnpilot_firmware";
	}
	hw_cpe = "cpe:/h:cambiumnetworks:cnpilot";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Cambium Networks cnPilot Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "cambium_cnpilot/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "cambium_cnpilot/http/" + port + "/concluded" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "cambium_cnpilot/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: os_name, version: detected_fw_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

