if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143419" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-01-29 07:11:46 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LANCOM Devices Detection Consolidation" );
	script_tag( name: "summary", value: "Reports LANCOM model and version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_lancom_devices_http_detect.sc", "gb_lancom_devices_snmp_detect.sc", "gb_lancom_devices_telnet_detect.sc", "gb_lancom_devices_telnetssl_detect.sc", "gb_lancom_devices_ssh_detect.sc", "gb_lancom_devices_sip_detect.sc" );
	script_mandatory_keys( "lancom/detected" );
	script_xref( name: "URL", value: "https://www.lancom-systems.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "lancom/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_version = "unknown";
for source in make_list( "http",
	 "telnet_ssl",
	 "snmp",
	 "telnet",
	 "ssh",
	 "sip/tcp",
	 "sip/udp" ) {
	version_list = get_kb_list( "lancom/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	model_list = get_kb_list( "lancom/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			break;
		}
	}
}
if( detected_model != "unknown" ){
	os_name = "LANCOM " + detected_model + " Firmware";
	hw_name = "LANCOM " + detected_model;
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:lancom:" + tolower( detected_model ) + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:lancom:" + tolower( detected_model ) + "_firmware";
	}
	hw_cpe = "cpe:/h:lancom:" + tolower( detected_model );
}
else {
	os_name = "LANCOM Unknown Model Firmware";
	hw_name = "LANCOM Unknown Model";
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:lancom:lancom_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:lancom:lancom_firmware";
	}
	hw_cpe = "cpe:/h:lancom:unknown_model";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "LANCOM Devices Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(http_ports = get_kb_list( "lancom/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "lancom/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "www" );
		register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "www" );
	}
}
if(telnetssl_ports = get_kb_list( "lancom/telnet_ssl/port" )){
	for port in telnetssl_ports {
		extra += "Telnet over SSL on port " + port + "/tcp\n";
		concluded = get_kb_item( "lancom/telnet_ssl/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "telnet" );
		register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "telnet" );
	}
}
if(snmp_ports = get_kb_list( "lancom/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "lancom/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
	}
}
if(telnet_ports = get_kb_list( "lancom/telnet/port" )){
	for port in telnet_ports {
		extra += "Telnet on port " + port + "/tcp\n";
		concluded = get_kb_item( "lancom/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "telnet" );
		register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "telnet" );
	}
}
if(ssh_ports = get_kb_list( "lancom/ssh/port" )){
	for port in ssh_ports {
		extra += "SSH banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "lancom/ssh/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "ssh" );
		register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "ssh" );
	}
}
if(sip_ports = get_kb_list( "lancom/sip/tcp/port" )){
	for port in sip_ports {
		extra += "SIP banner on port " + port + "/tcp\n";
		concluded = get_kb_item( "lancom/sip/tcp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "sip" );
		register_product( cpe: hw_cpe, location: port + "/tcp", port: port, service: "sip" );
	}
}
if(sip_ports = get_kb_list( "lancom/sip/udp/port" )){
	for port in sip_ports {
		extra += "SIP banner on port " + port + "/udp\n";
		concluded = get_kb_item( "lancom/sip/udp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: port + "/udp", port: port, service: "sip", proto: "udp" );
		register_product( cpe: hw_cpe, location: port + "/udp", port: port, service: "sip", proto: "udp" );
	}
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

