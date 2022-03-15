if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141684" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-11-14 15:35:48 +0700 (Wed, 14 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens SIMATIC HMI Device Detection Consolidation" );
	script_tag( name: "summary", value: "Report the Siemens SIMATIC HMI device model, hardware and firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_simatic_hmi_snmp_detect.sc", "gb_simatic_hmi_http_detect.sc" );
	script_mandatory_keys( "simatic_hmi/detected" );
	script_xref( name: "URL", value: "https://www.siemens.com/global/en/home/products/automation/simatic-hmi.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "simatic_hmi/detected" )){
	exit( 0 );
}
detected_fw_version = "unknown";
detected_hw_version = "unknown";
detected_model = "unknown";
for source in make_list( "http",
	 "snmp" ) {
	fw_version_list = get_kb_list( "simatic_hmi/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version && fw_version != "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "simatic_hmi/fw_version", value: fw_version );
			break;
		}
	}
	hw_version_list = get_kb_list( "simatic_hmi/" + source + "/*/hw_version" );
	for hw_version in hw_version_list {
		if(hw_version && hw_version != "unknown"){
			detected_hw_version = hw_version;
			set_kb_item( name: "simatic_hmi/hw_version", value: hw_version );
			break;
		}
	}
	model_list = get_kb_list( "simatic_hmi/" + source + "/*/model" );
	for model in model_list {
		if(model && model != "unknown"){
			detected_model = model;
			set_kb_item( name: "simatic_hmi/model", value: model );
			break;
		}
	}
}
if( ContainsString( detected_model, "Comfort" ) || !ContainsString( detected_model, "Basic" ) ){
	os_name = "Windows CE";
	os_cpe = "cpe:/o:microsoft:windows_ce";
}
else {
	os_name = "Siemens SIMATIC HMI OS";
	os_cpe = "cpe:/o:siemens:simatic_hmi_os";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Siemens SIMATIC HMI Device Detection Consolidation", runs_key: "windows" );
app_name = "Siemens SIMATIC HMI ";
hw_name = "Siemens SIMATIC HMI ";
if( detected_model != "unknown" ){
	_detected_model = str_replace( find: " ", string: detected_model, replace: "_" );
	_detected_model = tolower( _detected_model );
	app_name += detected_model + " Firmware";
	app_cpe = "cpe:/a:siemens:simatic_hmi_" + _detected_model + "_firmware";
	hw_name += detected_model;
	hw_cpe = "cpe:/h:siemens:simatic_hmi_" + _detected_model;
}
else {
	app_name += " Unknown Model Firmware";
	app_cpe = "cpe:/a:siemens:simatic_hmi_unknown_model_firmware";
	hw_name += " Unknown Model";
	hw_cpe = "cpe:/h:siemens:simatic_hmi_unknown_model";
}
if(detected_fw_version != "unknown"){
	app_cpe += ":" + detected_fw_version;
}
if(detected_hw_version != "unknown"){
	hw_cpe += ":" + detected_hw_version;
}
if(snmp_ports = get_kb_list( "simatic_hmi/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "simatic_hmi/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: app_cpe, location: port + "/tcp", port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "simatic_hmi/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: app_cpe, location: "/", port: port, service: "www" );
		register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
	}
}
report = build_detection_report( app: app_name, version: detected_fw_version, install: "/", cpe: app_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, version: detected_hw_version, install: "/", cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

