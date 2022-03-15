if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112450" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-12-06 11:27:12 +0100 (Thu, 06 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cradlepoint Routers Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_cradlepoint_router_snmp_detect.sc", "gb_cradlepoint_router_http_detect.sc" );
	script_mandatory_keys( "cradlepoint/router/detected" );
	script_tag( name: "summary", value: "The script reports a detected Cradlepoint router including the
  version number and exposed services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "cradlepoint/router/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw_version = "unknown";
for source in make_list( "snmp",
	 "http" ) {
	fw_version_list = get_kb_list( "cradlepoint/router/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version != "unknown" && detected_fw_version == "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "cradlepoint/router/fw_version", value: fw_version );
		}
	}
	model_list = get_kb_list( "cradlepoint/router/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "cradlepoint/router/model", value: model );
		}
	}
}
if( detected_model != "unknown" ){
	hw_cpe = "cpe:/h:cradlepoint:" + tolower( detected_model );
	app_type = detected_model;
}
else {
	hw_cpe = "cpe:/h:cradlepoint:unknown_model";
	app_type = "Unknown";
}
os_cpe = "cpe:/o:cradlepoint:firmware";
if(detected_fw_version != "unknown"){
	os_cpe += ":" + detected_fw_version;
}
os_register_and_report( os: "Cradlepoint Router Firmware", cpe: os_cpe, desc: "Cradlepoint Routers Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(snmp_ports = get_kb_list( "cradlepoint/router/snmp/port" )){
	for port in snmp_ports {
		concluded = get_kb_item( "cradlepoint/router/snmp/" + port + "/concluded" );
		extra += "SNMP on port " + port + "/udp\n";
		if(concluded){
			extra += "Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "cradlepoint/router/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "cradlepoint/router/http/" + port + "/concluded" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
report = build_detection_report( app: "Cradlepoint Router Firmware", version: detected_fw_version, install: location, cpe: os_cpe );
report += "\n\n" + build_detection_report( app: "Cradlepoint " + app_type + " Device", install: location, cpe: hw_cpe, skip_version: TRUE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

