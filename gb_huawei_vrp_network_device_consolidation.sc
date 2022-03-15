if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112731" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-01-15 02:15:18 +0000 (Wed, 15 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei VRP Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidates the Huawei Versatile Routing Platform (VRP) network devices detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_huawei_vrp_network_device_snmp_detect.sc", "gb_huawei_vrp_network_device_ssh_banner_detect.sc", "gb_huawei_vrp_network_device_http_detect.sc", "gb_huawei_vrp_network_device_ssh_login_detect.sc", "gb_huawei_vrp_network_device_telnet_detect.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_xref( name: "URL", value: "http://e.huawei.com/en/products/enterprise-networking/switches" );
	exit( 0 );
}
if(!get_kb_item( "huawei/vrp/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("huawei.inc.sc");
set_kb_item( name: "huawei/data_communication_product/detected", value: TRUE );
detected_version = "unknown";
detected_major_version = "unknown";
detected_model = "unknown";
detected_patch = "unknown";
for source in make_list( "ssh-login",
	 "snmp",
	 "http",
	 "ssh-banner",
	 "telnet" ) {
	version_list = get_kb_list( "huawei/vrp/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "huawei/vrp/version", value: version );
			break;
		}
	}
	model_list = get_kb_list( "huawei/vrp/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "huawei/vrp/model", value: model );
			break;
		}
	}
	major_version_list = get_kb_list( "huawei/vrp/" + source + "/major_version" );
	for major_version in major_version_list {
		if(major_version != "unknown" && detected_major_version == "unknown"){
			detected_major_version = major_version;
			set_kb_item( name: "huawei/vrp/major_version", value: major_version );
			break;
		}
	}
	if(detected_version != "unknown" && detected_model != "unknown"){
		break;
	}
}
if( detected_model != "unknown" ){
	os_name = "Huawei " + detected_model + " Versatile Routing Platform (VRP) network device Firmware";
	hw_name = "Huawei " + detected_model + " Versatile Routing Platform (VRP) network device";
	hw_cpe = "cpe:/h:huawei:" + tolower( detected_model );
	hw_cpe = str_replace( string: hw_cpe, find: " ", replace: "_" );
	os_cpe = build_cpe( value: tolower( detected_version ), exp: "^(v[0-9a-z]+)", base: "cpe:/o:huawei:" + tolower( detected_model ) + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:huawei:" + tolower( detected_model ) + "_firmware";
	}
	os_cpe = str_replace( string: os_cpe, find: " ", replace: "_" );
}
else {
	os_name = "Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware";
	hw_name = "Huawei Unknown Model Versatile Routing Platform (VRP) network device";
	os_cpe = build_cpe( value: tolower( detected_version ), exp: "^(v[0-9a-z]+)", base: "cpe:/o:huawei:vrp_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:huawei:vrp_firmware";
	}
	hw_cpe = "cpe:/h:huawei:vrp";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Huawei VRP Detection Consolidation", runs_key: "unixoide" );
huawei_sa_cpe = huawei_find_device( cpe_string: os_cpe );
location = "/";
extra = "";
if(ssh_ports = get_kb_list( "huawei/vrp/ssh-login/port" )){
	for port in ssh_ports {
		if(extra){
			extra += "\n\n";
		}
		extra += "SSH login on port " + port + "/tcp";
		concluded = get_kb_item( "huawei/vrp/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "\n  Concluded from version/product identification result:" + concluded;
		}
		concluded_command = get_kb_item( "huawei/vrp/ssh-login/" + port + "/concluded_command" );
		if(concluded_command){
			extra += "\n  Concluded from version/product identification command(s): " + concluded_command;
		}
		patch_version = get_kb_item( "huawei/vrp/ssh-login/" + port + "/patch" );
		if(patch_version){
			detected_patch = patch_version;
			if(detected_patch != "No patch installed"){
				set_kb_item( name: "huawei/vrp/patch", value: detected_patch );
			}
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh-login" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "ssh-login" );
		if(huawei_sa_cpe){
			register_product( cpe: huawei_sa_cpe, location: location, port: port, service: "ssh-login" );
		}
	}
}
if(snmp_ports = get_kb_list( "huawei/vrp/snmp/port" )){
	for port in snmp_ports {
		if(extra){
			extra += "\n\n";
		}
		extra += "SNMP on port " + port + "/udp";
		concluded = get_kb_item( "huawei/vrp/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "\n  Concluded from: " + concluded;
		}
		patch_version = get_kb_item( "huawei/vrp/snmp/" + port + "/patch" );
		if(patch_version){
			detected_patch = patch_version;
			if(detected_patch != "No patch installed"){
				set_kb_item( name: "huawei/vrp/patch", value: detected_patch );
			}
		}
		register_product( cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		if(huawei_sa_cpe){
			register_product( cpe: huawei_sa_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		}
	}
}
if(http_ports = get_kb_list( "huawei/vrp/http/port" )){
	for port in http_ports {
		if(extra){
			extra += "\n\n";
		}
		extra += "HTTP(s) on port " + port + "/tcp";
		concluded = get_kb_item( "huawei/vrp/http/" + port + "/concluded" );
		if(concluded){
			extra += "\n  Concluded from version/product identification result: " + concluded;
		}
		concluded_location = get_kb_item( "huawei/vrp/http/" + port + "/concluded_location" );
		if(concluded_location){
			extra += "\n  Concluded from version/product identification location: " + concluded_location;
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		if(huawei_sa_cpe){
			register_product( cpe: huawei_sa_cpe, location: location, port: port, service: "www" );
		}
	}
}
if(ssh_ports = get_kb_list( "huawei/vrp/ssh-banner/port" )){
	for port in ssh_ports {
		if(extra){
			extra += "\n\n";
		}
		extra += "SSH-Banner on port " + port + "/tcp";
		concluded = get_kb_item( "huawei/vrp/ssh-banner/" + port + "/concluded" );
		if(concluded){
			extra += "\n  Concluded from version/product identification result: " + concluded;
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "ssh" );
		if(huawei_sa_cpe){
			register_product( cpe: huawei_sa_cpe, location: location, port: port, service: "ssh" );
		}
	}
}
if(telnet_ports = get_kb_list( "huawei/vrp/telnet/port" )){
	for port in telnet_ports {
		if(extra){
			extra += "\n\n";
		}
		extra += "Telnet-Banner on port " + port + "/tcp";
		concluded = get_kb_item( "huawei/vrp/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "\n  Concluded from version/product identification result: " + concluded;
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "telnet" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "telnet" );
	}
}
if(detected_model != "unknown" && detected_major_version != "unknown" && detected_version != "unknown"){
	huawei_is_yunshan( model: detected_model, major_version: detected_major_version, version: detected_version );
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe, extra: "Patch Version: " + detected_patch );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

