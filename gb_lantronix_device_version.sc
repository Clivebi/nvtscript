if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108303" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-11-29 08:03:31 +0100 (Wed, 29 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Lantronix Devices Detection (Version)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_lantronix_device_detect_snmp.sc", "gb_lantronix_device_detect_telnet.sc", "gb_lantronix_mgm_tcp_detect.sc", "gb_lantronix_mgm_udp_detect.sc", "gb_lantronix_device_detect_http.sc" );
	script_mandatory_keys( "lantronix_device/detected" );
	script_tag( name: "summary", value: "The script reports a detected Lantronix device including the
  version number and exposed services." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "lantronix_device/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_type = "unknown";
for source in make_list( "snmp",
	 "telnet",
	 "http",
	 "lantronix_remote_conf_tcp",
	 "lantronix_remote_conf_udp" ) {
	version_list = get_kb_list( "lantronix_device/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			set_kb_item( name: "lantronix_device/version", value: version );
		}
	}
	type_list = get_kb_list( "lantronix_device/" + source + "/*/type" );
	for type in type_list {
		if(type != "unknown" && detected_type == "unknown"){
			detected_type = type;
			set_kb_item( name: "lantronix_device/type", value: type );
		}
	}
}
if( detected_type != "unknown" ){
	hw_cpe = "cpe:/h:lantronix:" + tolower( detected_type );
	sw_cpe = "cpe:/a:lantronix:" + tolower( detected_type ) + "_firmware";
	app_type = detected_type;
}
else {
	hw_cpe = "cpe:/h:lantronix:unknown_device";
	sw_cpe = "cpe:/a:lantronix:unknown_device_firmware";
	app_type = "Unknown";
}
if(detected_version != "unknown"){
	sw_cpe += ":" + detected_version;
}
location = "/";
if(snmp_ports = get_kb_list( "lantronix_device/snmp/port" )){
	for port in snmp_ports {
		concluded = get_kb_item( "lantronix_device/snmp/" + port + "/concluded" );
		extra += "SNMP on port " + port + "/udp\n";
		if(concluded){
			extra += "Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: sw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(telnet_ports = get_kb_list( "lantronix_device/telnet/port" )){
	for port in telnet_ports {
		concluded = get_kb_item( "lantronix_device/telnet/" + port + "/concluded" );
		extra += "Telnet on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "telnet" );
		register_product( cpe: sw_cpe, location: location, port: port, service: "telnet" );
	}
}
if(http_ports = get_kb_list( "lantronix_device/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "lantronix_device/http/" + port + "/concluded" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "Concluded: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: sw_cpe, location: location, port: port, service: "www" );
	}
}
if(lantronix_remote_conf_tcp_ports = get_kb_list( "lantronix_device/lantronix_remote_conf_tcp/port" )){
	for port in lantronix_remote_conf_tcp_ports {
		extra += "Lantronix Remote Configuration Protocol on port " + port + "/tcp\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "lantronix_remote_conf_tcp" );
		register_product( cpe: sw_cpe, location: location, port: port, service: "lantronix_remote_conf_tcp" );
		tmp_extracted = get_kb_item( "lantronix_device/lantronix_remote_conf_tcp/" + port + "/extracted" );
		if(tmp_extracted){
			extracted += "\n" + tmp_extracted;
		}
	}
}
if(lantronix_remote_conf_udp_ports = get_kb_list( "lantronix_device/lantronix_remote_conf_udp/port" )){
	for port in lantronix_remote_conf_udp_ports {
		extra += "Lantronix Remote Configuration Protocol on port " + port + "/udp\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "lantronix_remote_conf_udp", proto: "udp" );
		register_product( cpe: sw_cpe, location: location, port: port, service: "lantronix_remote_conf_udp", proto: "udp" );
		tmp_extracted = get_kb_item( "lantronix_device/lantronix_remote_conf_udp/" + port + "/extracted" );
		if(tmp_extracted){
			extracted += "\n" + tmp_extracted;
		}
	}
}
report = build_detection_report( app: "Lantronix " + app_type + " Firmware", version: detected_version, install: location, cpe: sw_cpe );
report += "\n\n" + build_detection_report( app: "Lantronix " + app_type + " Device", install: location, cpe: hw_cpe, skip_version: TRUE );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
if(extracted){
	report += "\n\nExtracted info from the Lantronix Remote Configuration Protocol:\n";
	report += "\n" + extracted;
}
log_message( port: 0, data: report );
exit( 0 );

