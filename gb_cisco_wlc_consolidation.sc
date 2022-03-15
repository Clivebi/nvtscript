require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105430" );
	script_version( "2021-06-11T11:26:00+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 11:26:00 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-10-30 14:22:49 +0100 (Fri, 30 Oct 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Wireless LAN Controller (WLC) Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Cisco Wireless LAN Controller (WLC) detections." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_snmp_detect.sc", "gb_cisco_wlc_ssh_login_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_cisco_wlc_http_detect.sc" );
	}
	script_mandatory_keys( "cisco/wlc/detected" );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html" );
	exit( 0 );
}
if(!get_kb_item( "cisco/wlc/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_model = "unknown";
detected_version = "unknown";
location = "/";
for source in make_list( "ssh-login",
	 "snmp",
	 "http" ) {
	version_list = get_kb_list( "cisco/wlc/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	model_list = get_kb_list( "cisco/wlc/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "cisco/wlc/model", value: detected_model );
			break;
		}
	}
}
os_cpe1 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:wireless_lan_controller_firmware:" );
os_cpe2 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:wireless_lan_controller_software:" );
if(!os_cpe1){
	os_cpe1 = "cpe:/o:cisco:wireless_lan_controller_firmware";
	os_cpe2 = "cpe:/o:cisco:wireless_lan_controller_software";
}
if( detected_model != "unknown" ){
	os_name = "Cisco Wireless LAN Controller " + detected_model + " Firmware";
	hw_name = "Cisco Wireless LAN Controller " + detected_model;
	os_cpe3 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:" + tolower( detected_model ) + "_wireless_lan_controller_firmware:" );
	os_cpe4 = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:" + tolower( detected_model ) + "_wireless_lan_controller_software:" );
	if(!os_cpe3){
		os_cpe3 = "cpe:/o:cisco:" + tolower( detected_model ) + "_wireless_lan_controller_firmware";
		os_cpe4 = "cpe:/o:cisco:" + tolower( detected_model ) + "_wireless_lan_controller_software";
	}
	hw_cpe = "cpe:/h:cisco:" + tolower( detected_model ) + "_wireless_lan_controller";
}
else {
	os_name = "Cisco Wireless LAN Controller Firmware";
	hw_name = "Cisco Wireless LAN Controller Unknown Model";
	hw_cpe = "cpe:/h:cisco:wireless_lan_controller";
}
os_register_and_report( os: os_name, cpe: os_cpe1, runs_key: "unixoide", desc: "Cisco Wireless LAN Controller (WLC) Detection Consolidation" );
if(ssh_login_ports = get_kb_list( "cisco/wlc/ssh-login/port" )){
	extra += "Local Detection over SSH:\n";
	for port in ssh_login_ports {
		concluded = get_kb_item( "cisco/wlc/ssh-login/" + port + "/concluded" );
		extra += "  Port:                           " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product identification result:\n" + concluded;
		}
		register_product( cpe: os_cpe1, location: location, port: port, service: "ssh-login" );
		register_product( cpe: os_cpe2, location: location, port: port, service: "ssh-login" );
		if(os_cpe3){
			register_product( cpe: os_cpe3, location: location, port: port, service: "ssh-login" );
			register_product( cpe: os_cpe4, location: location, port: port, service: "ssh-login" );
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "ssh-login" );
	}
}
if(snmp_ports = get_kb_list( "cisco/wlc/snmp/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Remote Detection over SNMP:\n";
	for port in snmp_ports {
		extra += "  Port:                " + port + "/udp\n";
		concludedVers = get_kb_item( "cisco/wlc/snmp/" + port + "/concludedVers" );
		concludedVersOID = get_kb_item( "cisco/wlc/snmp/" + port + "/concludedVersOID" );
		if(concludedVers && concludedVersOID){
			extra += "  Concluded from:      \"" + concludedVers + "\" via OID: \"" + concludedVersOID + "\"\n";
		}
		concluded = get_kb_item( "cisco/wlc/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  SNMP Banner:\n" + concluded + "\n";
		}
		register_product( cpe: os_cpe1, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe2, location: location, port: port, service: "snmp", proto: "udp" );
		if(os_cpe3){
			register_product( cpe: os_cpe3, location: location, port: port, service: "snmp", proto: "udp" );
			register_product( cpe: os_cpe4, location: location, port: port, service: "snmp", proto: "udp" );
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "cisco/wlc/http/port" )){
	if(extra){
		extra += "\n\n";
	}
	extra += "Remote Detection over HTTP(s):\n";
	for port in http_ports {
		extra += "  Port:                " + port + "/tcp\n";
		concluded = get_kb_item( "cisco/wlc/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result:  " + concluded;
		}
		register_product( cpe: os_cpe1, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe2, location: location, port: port, service: "www" );
		if(os_cpe3){
			register_product( cpe: os_cpe3, location: location, port: port, service: "www" );
			register_product( cpe: os_cpe4, location: location, port: port, service: "www" );
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
	}
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe1 );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

