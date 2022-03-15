if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144354" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-05 05:42:19 +0000 (Wed, 05 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ZHONE ZNID GPON Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of ZHONE ZNID GPON detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_zhone_znid_gpon_snmp_detect.sc", "gb_zhone_znid_gpon_telnet_detect.sc" );
	script_mandatory_keys( "dasanzhone/znid/detected" );
	script_xref( name: "URL", value: "https://dasanzhone.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "dasanzhone/znid/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_version = "unknown";
location = "/";
for source in make_list( "snmp",
	 "telnet" ) {
	version_list = get_kb_list( "dasanzhone/znid/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	model_list = get_kb_list( "dasanzhone/znid/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "dasanzhone/znid/model", value: detected_model );
			break;
		}
	}
}
if( detected_model != "unknown" ){
	os_name = "ZHONE ZNID GPON " + detected_model + " Firmware";
	hw_name = "ZHONE ZNID GPON " + detected_model;
	cpe_model = tolower( str_replace( string: detected_model, find: "-", replace: "_" ) );
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:dasanzhone:znid_" + cpe_model + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:dasanzhone:znid_" + cpe_model + "_firmware";
	}
	hw_cpe = "cpe:/h:dasanzhone:znid_" + cpe_model;
}
else {
	os_name = "ZHONE ZNID GPON Unknown Model Firmware";
	hw_name = "ZHONE ZNID GPON Unknown Model";
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:dasanzhone:znid_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:dasanzhone:znid_firmware";
	}
	hw_cpe = "cpe:/h:dasanzhone:znid";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "ZHONE ZNID GPON Detection Consolidation", runs_key: "unixoide" );
if(snmp_ports = get_kb_list( "dasanzhone/znid/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "dasanzhone/znid/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  SNMP Banner: " + concluded + "\n";
		}
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(telnet_ports = get_kb_list( "dasanzhone/znid/telnet/port" )){
	for port in telnet_ports {
		extra += "Telnet on port " + port + "/tcp\n";
		concluded = get_kb_item( "dasanzhone/znid/telnet/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
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
log_message( port: 0, data: report );
exit( 0 );

