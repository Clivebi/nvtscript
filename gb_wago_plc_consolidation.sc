if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141766" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-12-07 12:20:20 +0700 (Fri, 07 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WAGO PLC Detection Consolidation" );
	script_tag( name: "summary", value: "Reports the WAGO PLC Controller model and firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_wago_plc_http_detect.sc", "gb_wago_plc_snmp_detect.sc", "gb_wago_plc_ethernetip_detect.sc" );
	script_mandatory_keys( "wago_plc/detected" );
	script_xref( name: "URL", value: "https://www.wago.com/global/c/plcs-%E2%80%93-controllers" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "wago_plc/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw_version = "unknown";
for source in make_list( "http",
	 "ethernetip",
	 "opcua",
	 "snmp" ) {
	fw_version_list = get_kb_list( "wago_plc/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version && fw_version != "unknown"){
			if( detected_fw_version == "unknown" ){
				detected_fw_version = fw_version;
				set_kb_item( name: "wago_plc/fw_version", value: fw_version );
			}
			else {
				if(version_is_greater( version: fw_version, test_version: detected_fw_version )){
					detected_fw_version = fw_version;
					set_kb_item( name: "wago_plc/fw_version", value: fw_version );
				}
			}
		}
	}
	model_list = get_kb_list( "wago_plc/" + source + "/*/model" );
	for model in model_list {
		if(model && model != "unknown"){
			detected_model = model;
			set_kb_item( name: "wago_plc/model", value: model );
			break;
		}
	}
}
app_name = "WAGO PLC Controller ";
if( detected_model != "unknown" ){
	app_name += detected_model;
	mod = eregmatch( pattern: "([0-9]+-[0-9]+)", string: detected_model );
	if( !isnull( mod[1] ) ){
		app_cpe = "cpe:/a:wago:" + mod[1];
		os_cpe = "cpe:/o:wago:" + mod[1] + "_firmware";
		hw_cpe = "cpe:/h:wago:" + mod[1];
	}
	else {
		app_cpe = "cpe:/a:wago:plc";
		os_cpe = "cpe:/o:wago:plc_firmware";
		hw_cpe = "cpe:/h:wago:plc";
	}
}
else {
	app_cpe = "cpe:/a:wago:plc";
	os_cpe = "cpe:/o:wago:plc_firmware";
	hw_cpe = "cpe:/h:wago:plc";
}
if(detected_fw_version != "unknown"){
	app_cpe += ":" + detected_fw_version;
	os_cpe += ":" + detected_fw_version;
}
os_register_and_report( os: "WAGO PLC Controller Firmware", cpe: os_cpe, desc: "WAGO PLC Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(http_ports = get_kb_list( "wago_plc/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "wago_plc/http/" + port + "/concluded" );
		concUrl = get_kb_item( "wago_plc/http/" + port + "/concUrl" );
		mac = get_kb_item( "wago_plc/http/" + port + "/mac" );
		if(mac){
			macaddr = "MAC address:    " + mac;
		}
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		if(concUrl){
			extra += "  Concluded from version/product identification location:" + concUrl + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: app_cpe, location: location, port: port, service: "www" );
	}
}
if(ether_ports = get_kb_list( "wago_plc/ethernetip/port" )){
	for port in ether_ports {
		if(ether_protos = get_kb_list( "wago_plc/ethernetip/" + port + "/proto" )){
			for proto in ether_protos {
				extra += "EtherNet/IP on port " + port + "/" + proto + "\n";
				register_product( cpe: hw_cpe, location: location, port: port, service: "ethernetip", proto: proto );
				register_product( cpe: os_cpe, location: location, port: port, service: "ethernetip", proto: proto );
				register_product( cpe: app_cpe, location: location, port: port, service: "ethernetip", proto: proto );
			}
		}
	}
}
if(opc_ports = get_kb_list( "wago_plc/opcua/port" )){
	for port in opc_ports {
		extra += "OPC-UA on port " + port + "/tcp\n";
		if( opc_version = get_kb_item( "wago_plc/opcua/" + port + "/opc_version" ) ){
			extra += "  OPC-UA Version:  " + opc_version + "\n";
			opc_cpe = "cpe:/a:wago/opcua_server:" + opc_version;
		}
		else {
			opc_cpe = "cpe:/a:wago/opcua_server";
		}
		if(build = get_kb_item( "wago_plc/opcua/" + port + "/build" )){
			extra += "  OPC-UA Build:    " + build + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "opc-ua" );
		register_product( cpe: os_cpe, location: location, port: port, service: "opc-ua" );
		register_product( cpe: opc_cpe, location: location, port: port, service: "opc-ua" );
	}
}
if(snmp_ports = get_kb_list( "wago_plc/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "wago_plc/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: app_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
	}
}
report += build_detection_report( app: app_name + " Firmware", version: detected_fw_version, install: "/", cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: app_name, version: detected_fw_version, install: "/", cpe: app_cpe );
report += "\n\n";
report += build_detection_report( app: app_name, install: "/", cpe: hw_cpe, skip_version: TRUE, extra: macaddr );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

