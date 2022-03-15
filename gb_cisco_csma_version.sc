if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105433" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-11-06 12:16:22 +0100 (Fri, 06 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cisco Content Security Management Appliance Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_ironport_csma_detect.sc", "gather-package-list.sc" );
	script_mandatory_keys( "cisco_csm/detected" );
	script_tag( name: "summary", value: "This Script consolidates the via HTTP(s) and/or SSH detected Cisco Content Security
  Management Appliance version." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "cisco_csm/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_version = "unknown";
for source in make_list( "http",
	 "ssh-login" ) {
	model_list = get_kb_list( "cisco_csm/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "cisco_csm/model", value: detected_model );
		}
	}
	vers_list = get_kb_list( "cisco_csm/" + source + "/*/version" );
	for vers in vers_list {
		if(vers != "unknown" && detected_version == "unknown"){
			detected_version = vers;
			set_kb_item( name: "cisco_csm/version", value: detected_version );
		}
	}
}
os_register_and_report( os: "Cisco AsyncOS", cpe: "cpe:/o:cisco:asyncos", desc: "Cisco Content Security Management Appliance Detection Consolidation", runs_key: "unixoide" );
app_name = "Cisco Content Security Management Appliance";
if(detected_model != "unknown"){
	app_name += " " + detected_model;
}
cpe = "cpe:/a:cisco:content_security_management_appliance";
if(detected_version != "unknown"){
	cpe += ":" + detected_version;
}
location = "/";
extra = "";
if(http_ports = get_kb_list( "cisco_csm/http/port" )){
	for port in http_ports {
		if(extra){
			extra += "\n";
		}
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concl = get_kb_item( "cisco_csm/http/" + port + "/concluded" );
		if(concl){
			extra += "  Concluded from:\n" + concl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(ssh_ports = get_kb_list( "cisco_csm/ssh-login/port" )){
	for port in ssh_ports {
		if(extra){
			extra += "\n";
		}
		extra += "SSH login on port " + port + "/tcp\n";
		concluded = get_kb_item( "cisco_csm/ssh-login/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from \"version\" SSH command response:\n" + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "ssh-login" );
	}
}
report = build_detection_report( app: app_name, version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

