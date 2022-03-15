if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141824" );
	script_version( "2021-09-06T12:21:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 12:21:43 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-04 13:08:39 +0700 (Fri, 04 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Xerox Printer Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Xerox printer detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_xerox_printer_http_detect.sc", "gb_xerox_printer_snmp_detect.sc", "gb_xerox_printer_pjl_detect.sc", "global_settings.sc" );
	script_mandatory_keys( "xerox/printer/detected" );
	script_xref( name: "URL", value: "https://www.xerox.com/en-us/printing-equipment" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("xerox_printers.inc.sc");
if(!get_kb_item( "xerox/printer/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw_version = "unknown";
for source in make_list( "snmp",
	 "http",
	 "hp-pjl" ) {
	fw_version_list = get_kb_list( "xerox/printer/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version && detected_fw_version == "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "xerox/printer/fw_version", value: fw_version );
		}
	}
	model_list = get_kb_list( "xerox/printer/" + source + "/*/model" );
	for model in model_list {
		if(model && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "xerox/printer/model", value: model );
		}
	}
}
os_name = "Xerox Printer ";
if( detected_model != "unknown" ){
	os_name += detected_model + " Firmware";
	hw_name += detected_model;
	hw_cpe = build_xerox_cpe( model: detected_model );
	os_cpe = str_replace( string: hw_cpe, find: "cpe:/h", replace: "cpe:/o" );
	os_cpe += "_firmware";
}
else {
	os_name += "Unknown Model Firmware";
	hw_name += "Unknown Model";
	hw_cpe = "cpe:/h:xerox:printer";
	os_cpe = "cpe:/o:xerox:printer_firmware";
}
if(detected_fw_version != "unknown"){
	os_cpe += ":" + detected_fw_version;
}
location = "/";
if(http_ports = get_kb_list( "xerox/printer/http/port" )){
	for port in http_ports {
		concluded = get_kb_item( "xerox/printer/http/" + port + "/concluded" );
		concUrl = get_kb_item( "xerox/printer/http/" + port + "/concludedUrl" );
		extra += "HTTP(s) on port " + port + "/tcp\n";
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "xerox/printer/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "xerox/printer/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from SNMP sysDescr OID: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
if(pjl_ports = get_kb_list( "xerox/printer/hp-pjl/port" )){
	for port in pjl_ports {
		extra += "PJL on port " + port + "/tcp\n";
		concluded = get_kb_item( "xerox/printer/hp-pjl/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from PJL banner: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "hp-pjl" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "hp-pjl" );
	}
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Xerox Printer Detection Consolidation", runs_key: "unixoide" );
report += build_detection_report( app: os_name, version: detected_fw_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
pref = get_kb_item( "global_settings/exclude_printers" );
if(pref == "yes"){
	log_message( port: 0, data: "The remote host is a printer. The scan has been disabled against this host.\n" + "If you want to scan the remote host, uncheck the \"Exclude printers from scan\" " + "option and re-scan it." );
	set_kb_item( name: "Host/dead", value: TRUE );
}
exit( 0 );

