if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105263" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-04-22 14:02:11 +0200 (Wed, 22 Apr 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Palo Alto PAN-OS Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc", "gb_palo_alto_version_api.sc" );
	script_mandatory_keys( "palo_alto/detected" );
	script_tag( name: "summary", value: "Consolidation of Palo Alto PAN-OS detections." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!system = get_kb_item( "palo_alto/detected" )){
	exit( 0 );
}
detected_fw_version = "unknown";
detected_fw_hotfix = "unknown";
detected_model = "unknown";
for source in make_list( "ssh",
	 "xml-api",
	 "webui" ) {
	if( source == "ssh" ){
		vpattern = "sw-version: ([^ \r\n]+)";
		mpattern = "model: ([^ \r\n]+)";
	}
	else {
		if( source == "xml-api" ){
			vpattern = "<sw-version>([^<]+)</sw-version>";
			mpattern = "<model>([^<]+)</model>";
		}
		else {
			continue;
		}
	}
	system_list = get_kb_list( "palo_alto/" + source + "/*/system" );
	for system in system_list {
		version = eregmatch( pattern: vpattern, string: system );
		if(!isnull( version[1] ) && detected_fw_version == "unknown"){
			detected_fw_version = version[1];
			if(ContainsString( detected_fw_version, "-h" )){
				version_and_hotfix = split( buffer: detected_fw_version, sep: "-h", keep: FALSE );
				detected_fw_version = version_and_hotfix[0];
				detected_fw_hotfix = version_and_hotfix[1];
			}
		}
		model = eregmatch( pattern: mpattern, string: system );
		if(!isnull( model[1] ) && detected_model == "unknown"){
			detected_model = model[1];
		}
	}
}
os_app = "Palo Alto PAN-OS";
os_cpe = "cpe:/o:paloaltonetworks:pan-os";
hw_app = "Palo Alto";
hw_cpe = "cpe:/h:paloaltonetworks";
if(detected_fw_version != "unknown"){
	set_kb_item( name: "palo_alto_pan_os/version", value: detected_fw_version );
	os_cpe += ":" + detected_fw_version;
	os_version = detected_fw_version;
}
if( detected_model != "unknown" ){
	set_kb_item( name: "palo_alto_pan_os/model", value: detected_model );
	hw_app += " " + detected_model;
	hw_cpe += ":" + tolower( detected_model );
}
else {
	hw_app += " Unknown Model";
	hw_cpe += ":unknown_model";
}
if(detected_fw_hotfix != "unknown" && detected_fw_version != "unknown"){
	set_kb_item( name: "palo_alto_pan_os/hotfix", value: detected_fw_hotfix );
	os_cpe += "-h" + detected_fw_hotfix;
	os_version = detected_fw_version + " Hotfix " + detected_fw_hotfix;
}
if( os_version ){
	os_register_and_report( os: "Palo Alto PAN-OS " + os_version, cpe: os_cpe, desc: "Palo Alto PAN-OS Detection Consolidation", runs_key: "unixoide" );
}
else {
	os_register_and_report( os: "Palo Alto PAN-OS", cpe: os_cpe, desc: "Palo Alto PAN-OS Detection Consolidation", runs_key: "unixoide" );
}
location = "/";
if(webui_ports = get_kb_list( "palo_alto/webui/port" )){
	for port in webui_ports {
		concluded = get_kb_item( "palo_alto/webui/" + port + "/concluded" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		failed = get_kb_item( "palo_alto/xml-api/" + port + "/fail_reason" );
		if(failed){
			failed_reasons += failed + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
	}
}
if(xml_api_ports = get_kb_list( "palo_alto/xml-api/port" )){
	for port in xml_api_ports {
		concluded = get_kb_item( "palo_alto/xml-api/" + port + "/concluded" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded from: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "xml-api" );
		register_product( cpe: os_cpe, location: location, port: port, service: "xml-api" );
	}
}
if(ssh_ports = get_kb_list( "palo_alto/ssh/port" )){
	for port in ssh_ports {
		extra += "SSH login on port " + port + "/tcp\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "ssh" );
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh" );
	}
}
report = build_detection_report( app: os_app, version: os_version, install: location, cpe: os_cpe );
report += "\n\n" + build_detection_report( app: hw_app, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
if(failed_reasons){
	report += "\n\nXML-API credentials where provided via \"Palo Alto PAN-OS Version Detection (XML-API)\" ";
	report += "(OID:1.3.6.1.4.1.25623.1.0.105262) but the login at the XML-API failed for the following reasons:\n";
	report += "\n" + failed_reasons;
}
log_message( port: 0, data: report );
exit( 0 );

