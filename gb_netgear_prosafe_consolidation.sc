if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108307" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-12-05 09:03:31 +0100 (Tue, 05 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NETGEAR ProSAFE Devices Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_netgear_prosafe_snmp_detect.sc", "gb_netgear_prosafe_http_detect.sc", "gb_netgear_prosafe_telnet_detect.sc" );
	script_mandatory_keys( "netgear/prosafe/detected" );
	script_tag( name: "summary", value: "Consolidation of NETGEAR ProSAFE device detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "netgear/prosafe/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw_version = "unknown";
detected_fw_build = "unknown";
for source in make_list( "snmp",
	 "http",
	 "telnet" ) {
	fw_version_list = get_kb_list( "netgear/prosafe/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version != "unknown" && detected_fw_version == "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "netgear/prosafe/fw_version", value: fw_version );
		}
	}
	model_list = get_kb_list( "netgear/prosafe/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "netgear/prosafe/model", value: model );
		}
	}
	fw_build_list = get_kb_list( "netgear/prosafe/" + source + "/*/fw_build" );
	for fw_build in fw_build_list {
		if(fw_build != "unknown" && detected_fw_build == "unknown"){
			detected_fw_build = fw_build;
			set_kb_item( name: "netgear/prosafe/fw_build", value: fw_build );
		}
	}
}
if( detected_model != "unknown" ){
	os_cpe = build_cpe( value: detected_fw_version, exp: "^([0-9.]+)", base: "cpe:/o:netgear:" + tolower( detected_model ) + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:netgear:" + tolower( detected_model ) + "_firmware";
	}
	hw_cpe = "cpe:/h:netgear:" + tolower( detected_model );
	app_type = detected_model;
}
else {
	os_cpe = build_cpe( value: detected_fw_version, exp: "^([0-9.]+)", base: "cpe:/o:netgear:prosafe_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:netgear:prosafe_firmware";
	}
	hw_cpe = "cpe:/h:netgear:prosafe";
	app_type = "Unknown";
}
if(detected_fw_build != "unknown"){
	fw_extra = "Build " + detected_fw_build;
}
os_register_and_report( os: "NETGEAR ProSAFE Firmware", cpe: os_cpe, desc: "NETGEAR ProSAFE Devices Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(snmp_ports = get_kb_list( "netgear/prosafe/snmp/port" )){
	for port in snmp_ports {
		concluded = get_kb_item( "netgear/prosafe/snmp/" + port + "/concluded" );
		extra += "SNMP on port " + port + "/udp\n";
		if(concluded){
			extra += "  Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "netgear/prosafe/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "netgear/prosafe/http/" + port + "/concluded" );
		concUrl = get_kb_item( "netgear/prosafe/http/" + port + "/concludedUrl" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from: " + concluded + "\n";
		}
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
if(telnet_ports = get_kb_list( "netgear/prosafe/telnet/port" )){
	for port in telnet_ports {
		concluded = get_kb_item( "netgear/prosafe/telnet/" + port + "/concluded" );
		extra += "Telnet on port " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "telnet" );
		register_product( cpe: os_cpe, location: location, port: port, service: "telnet" );
	}
}
report = build_detection_report( app: "NETGEAR ProSAFE " + app_type + " Firmware", version: detected_fw_version, install: location, extra: fw_extra, cpe: os_cpe );
report += "\n\n" + build_detection_report( app: "NETGEAR ProSAFE " + app_type + " Device", install: location, cpe: hw_cpe, skip_version: TRUE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

