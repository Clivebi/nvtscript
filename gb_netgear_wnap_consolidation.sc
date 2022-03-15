if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141740" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-11-29 16:18:35 +0700 (Thu, 29 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NETGEAR WNAP/WNDAP Device Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of NETGEAR WNAP/WNDAP device detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_netgear_wnap_snmp_detect.sc", "gb_netgear_wnap_http_detect.sc" );
	script_mandatory_keys( "netgear_wnap/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "netgear_wnap/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw_version = "unknown";
for source in make_list( "snmp",
	 "http" ) {
	model_list = get_kb_list( "netgear_wnap/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "netgear_wnap/model", value: model );
		}
	}
	fw_version_list = get_kb_list( "netgear_wnap/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version != "unknown" && detected_fw_version == "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "netgear_wnap/fw_version", value: fw_version );
		}
	}
}
if( detected_model != "unknown" ){
	os_name = "NETGEAR " + detected_model + " Firmware";
	hw_name = "NETGEAR " + detected_model;
	hw_cpe = "cpe:/h:netgear:" + tolower( detected_model );
	os_cpe = "cpe:/o:netgear:" + tolower( detected_model );
}
else {
	os_name = "NETGEAR WNAP/WNDAP Unknown Model Firmware";
	hw_name = "NETGEAR WNAP/WNDAP Unknown Model";
	hw_cpe = "cpe:/h:netgear:wnap";
	os_cpe = "cpe:/o:netgear:wnap_firmware";
}
location = "/";
if(detected_fw_version != "unknown"){
	os_cpe += ":" + detected_fw_version;
}
if(snmp_ports = get_kb_list( "netgear_wnap/snmp/port" )){
	for port in snmp_ports {
		concluded = get_kb_item( "netgear_wnap/snmp/" + port + "/concluded" );
		extra += "SNMP on port " + port + "/udp\n";
		if(concluded){
			extra += "  Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "netgear_wnap/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "NETGEAR WNAP/WNDAP Device Detection Consolidation", runs_key: "unixoide" );
report = build_detection_report( app: os_name, version: detected_fw_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, install: location, cpe: hw_cpe, skip_version: TRUE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

