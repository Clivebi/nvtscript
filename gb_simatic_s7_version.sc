if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106096" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-06-15 15:30:33 +0700 (Wed, 15 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens SIMATIC S7 Device Detection Consolidation" );
	script_tag( name: "summary", value: "Report the Siemens SIMATIC S7 device model and firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_simatic_s7_cotp_detect.sc", "gb_simatic_s7_snmp_detect.sc", "gb_simatic_s7_http_detect.sc" );
	script_mandatory_keys( "simatic_s7/detected" );
	script_xref( name: "URL", value: "https://www.siemens.com/global/en/home/products/automation/systems/industrial/plc.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "simatic_s7/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_model = "unknown";
for source in make_list( "cotp",
	 "snmp",
	 "http" ) {
	if(detected_version != "unknown"){
		break;
	}
	version_list = get_kb_list( "simatic_s7/" + source + "/*/version" );
	for version in version_list {
		if(version){
			detected_version = version;
			set_kb_item( name: "simatic_s7/version", value: version );
		}
	}
}
for source in make_list( "cotp",
	 "snmp",
	 "http" ) {
	if(detected_model != "unknown"){
		break;
	}
	model_list = get_kb_list( "simatic_s7/" + source + "/model" );
	for model in model_list {
		if(model){
			detected_model = model;
			set_kb_item( name: "simatic_s7/model", value: model );
		}
	}
}
if( detected_model != "unknown" ){
	app_name = "Siemens SIMATIC S7 " + detected_model;
	cpe_model = tolower( ereg_replace( pattern: "[ /]", string: detected_model, replace: "_" ) );
	app_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:siemens:simatic_s7_" + cpe_model + ":" );
	if(!app_cpe){
		app_cpe = "cpe:/a:siemens:simatic_s7_" + cpe_model;
	}
	os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:siemens:simatic_s7_cpu_" + cpe_model + "_firmware:" );
	if(!os_cpe){
		os_cpe = "cpe:/o:siemens:simatic_s7_cpu_" + cpe_model + "_firmware";
	}
}
else {
	app_name = "Siemens SIMATIC S7 Unknown Model";
	if( detected_version != "unknown" ){
		app_cpe = "cpe:/a:siemens:simatic_s7:" + detected_version;
		os_cpe = "cpe:/o:siemens:simatic_s7_cpu_firmware:" + detected_version;
	}
	else {
		app_cpe = "cpe:/a:siemens:simatic_s7";
		os_cpe = "cpe:/o:siemens:simatic_s7_cpu_firmware";
	}
}
if(cotp_ports = get_kb_list( "simatic_s7/cotp/port" )){
	for port in cotp_ports {
		extra += "COTP on port " + port + "/tcp\n";
		mod_type = get_kb_item( "simatic_s7/cotp/modtype" );
		if(mod_type){
			extra += "  Module Type:   " + mod_type + "\n";
			replace_kb_item( name: "simatic_s7/modtype", value: mod_type );
		}
		module = get_kb_item( "simatic_s7/cotp/module" );
		if(module){
			extra += "  Module:        " + module + "\n";
		}
		register_product( cpe: app_cpe, location: port + "/tcp", port: port, service: "cotp" );
		register_product( cpe: os_cpe, location: port + "/tcp", port: port, service: "cotp" );
	}
}
if(snmp_ports = get_kb_list( "simatic_s7/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		mod_type = get_kb_item( "simatic_s7/snmp/modtype" );
		if(mod_type){
			extra += "  Module Type:   " + mod_type + "\n";
			replace_kb_item( name: "simatic_s7/modtype", value: mod_type );
		}
		module = get_kb_item( "simatic_s7/snmp/module" );
		if(module){
			extra += "  Module:        " + module + "\n";
		}
		register_product( cpe: app_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
		register_product( cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp" );
	}
}
if(http_ports = get_kb_list( "simatic_s7/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		mod_type = get_kb_item( "simatic_s7/http/modtype" );
		if(mod_type){
			extra += "  Module Type:   " + mod_type + "\n";
			replace_kb_item( name: "simatic_s7/modtype", value: mod_type );
		}
		module = get_kb_item( "simatic_s7/http/module" );
		if(module){
			extra += "  Module:        " + module + "\n";
		}
		register_product( cpe: app_cpe, location: "/", port: port, service: "www" );
		register_product( cpe: os_cpe, location: "/", port: port, service: "www" );
	}
}
if(!ContainsString( extra, "SoftPLC" )){
	os_register_and_report( os: "Siemens SIMATIC S7 CPU Firmware", cpe: os_cpe, desc: "Siemens SIMATIC S7 Device Version", runs_key: "unixoide" );
}
report = build_detection_report( app: app_name, version: detected_version, install: "/", cpe: app_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

