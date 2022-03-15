require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105659" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-05-09 15:46:47 +0200 (Mon, 09 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco IOS XE Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_cisco_ios_xe_ssh_login_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_cisco_ios_xe_snmp_detect.sc" );
	}
	script_mandatory_keys( "cisco/ios_xe/detected" );
	script_tag( name: "summary", value: "Consolidation of Cisco IOS XE detections." );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xe/index.html" );
	exit( 0 );
}
if(!get_kb_item( "cisco/ios_xe/detected" )){
	exit( 0 );
}
require("cisco_ios.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_model = "unknown";
detected_version = "unknown";
detected_image = "unknown";
location = "/";
os_name = "Cisco IOS XE";
for source in make_list( "ssh-login",
	 "snmp" ) {
	version_list = get_kb_list( "cisco/ios_xe/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = iosver_2_iosxe_ver( iosver: version );
			break;
		}
	}
	model_list = get_kb_list( "cisco/ios_xe/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "cisco/ios_xe/model", value: detected_model );
			break;
		}
	}
	image_list = get_kb_list( "cisco/ios_xe/" + source + "/*/image" );
	for image in image_list {
		if(image != "unknown" && detected_image == "unknown"){
			detected_image = image;
			set_kb_item( name: "cisco/ios_xe/image", value: detected_image );
			break;
		}
	}
}
os_cpe = build_cpe( value: detected_version, exp: "^([0-9A-Z.]+)", base: "cpe:/o:cisco:ios_xe:" );
if(!os_cpe){
	os_cpe = "cpe:/o:cisco:ios_xe";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Cisco IOS XE Detection Consolidation", runs_key: "unixoide" );
if(detected_model != "unknown"){
	os_name += " on " + detected_model;
	hw_cpe = "cpe:/h:cisco:" + str_replace( string: tolower( detected_model ), find: " ", replace: "_" );
}
if(snmp_ports = get_kb_list( "cisco/ios_xe/snmp/port" )){
	extra += "Remote Detection over SNMP:\n";
	for port in snmp_ports {
		extra += "  Port:                " + port + "/udp\n";
		concludedVers = get_kb_item( "cisco/ios_xe/snmp/" + port + "/concludedVers" );
		concludedVersOID = get_kb_item( "cisco/ios_xe/snmp/" + port + "/concludedVersOID" );
		if(concludedVers && concludedVersOID){
			extra += "  Concluded from:      \"" + concludedVers + "\" via OID: \"" + concludedVersOID + "\"\n";
		}
		concluded = get_kb_item( "cisco/ios_xe/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  SNMP Banner:\n" + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		if(hw_cpe){
			register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		}
	}
}
if(ssh_login_ports = get_kb_list( "cisco/ios_xe/ssh-login/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Local Detection over SSH:\n";
	for port in ssh_login_ports {
		concluded = get_kb_item( "cisco/ios_xe/ssh-login/" + port + "/concluded" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product identification result:\n" + concluded;
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "ssh-login" );
		if(hw_cpe){
			register_product( cpe: hw_cpe, location: location, port: port, service: "ssh-login" );
		}
	}
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe );
if(hw_cpe){
	report += "\n\n";
	report += build_detection_report( app: "Cisco " + detected_model, skip_version: TRUE, install: location, cpe: hw_cpe );
}
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

