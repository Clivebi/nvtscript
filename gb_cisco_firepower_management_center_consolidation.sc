if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105522" );
	script_version( "2021-01-14T13:25:59+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-14 13:25:59 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-01-19 18:05:56 +0100 (Tue, 19 Jan 2016)" );
	script_name( "Cisco Firepower Management Center (FMC) Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Cisco Firepower Management Center (FMC) detections." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firepower_management_center_ssh_detect.sc", "gb_cisco_firepower_management_center_http_detect.sc" );
	script_mandatory_keys( "cisco/firepower_management_center/detected" );
	exit( 0 );
}
if(!get_kb_item( "cisco/firepower_management_center/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "http" ) {
	model_list = get_kb_list( "cisco/firepower_management_center/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "cisco/firepower_management_center/model", value: model );
			break;
		}
	}
	version_list = get_kb_list( "cisco/firepower_management_center/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	build_list = get_kb_list( "cisco/firepower_management_center/" + source + "/*/build" );
	for build in build_list {
		if(build != "unknown" && detected_build == "unknown"){
			detected_build = build;
			set_kb_item( name: "cisco/firepower_management_center/build", value: build );
			break;
		}
	}
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:firepower_management_center:" );
if(!cpe){
	cpe = "cpe:/a:cisco:firepower_management_center";
}
if(http_ports = get_kb_list( "cisco/firepower_management_center/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concUrl = get_kb_item( "cisco/firepower_management_center/http/" + port + "/concludedUrl" );
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(ssh_login_ports = get_kb_list( "cisco/firepower_management_center/ssh-login/port" )){
	for port in ssh_login_ports {
		extra += "SSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "cisco/firepower_management_center/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
report = build_detection_report( app: "Cisco Firepower Management Center (FMC)", version: detected_version, install: location, cpe: cpe, extra: "Build: " + detected_build + "\nModel: " + detected_model );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

