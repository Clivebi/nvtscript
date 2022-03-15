if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144115" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-06-16 09:39:02 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Geneko Router Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Geneko router detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_geneko_router_http_detect.sc", "gb_geneko_router_snmp_detect.sc", "gb_geneko_router_telnet_detect.sc" );
	script_mandatory_keys( "geneko/router/detected" );
	exit( 0 );
}
if(!get_kb_item( "geneko/router/detected" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
detected_model = "unknown";
location = "/";
os_name = "Geneko Router Unknown Model Firmware";
hw_name = "Geneko Router Unknown Model";
os_cpe = "cpe:/o:geneko:router_firmware";
hw_cpe = "cpe:/h:geneko:router";
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Geneko Router Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "geneko/router/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "geneko/router/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "geneko/router/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  SNMP Banner: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(telnet_ports = get_kb_list( "geneko/router/telnet/port" )){
	for port in telnet_ports {
		extra += "Telnet on port " + port + "/tcp\n";
		concluded = get_kb_item( "geneko/router/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "  Telnet Banner: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "telnet" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "telnet" );
	}
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: chomp( report ) );
exit( 0 );

