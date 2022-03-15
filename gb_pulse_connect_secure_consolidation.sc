require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144350" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-04 05:14:24 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Pulse Connect Secure Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Pulse Connect Secure detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_pulse_connect_secure_snmp_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_pulse_connect_secure_http_detect.sc" );
	}
	script_mandatory_keys( "pulsesecure/detected" );
	script_xref( name: "URL", value: "https://www.pulsesecure.net/products/pulse-connect-secure/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "pulsesecure/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_model = "unknown";
location = "/";
for source in make_list( "snmp",
	 "http" ) {
	version_list = get_kb_list( "pulsesecure/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	model_list = get_kb_list( "pulsesecure/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "pulsesecure/model", value: detected_model );
			break;
		}
	}
}
name = "Pulse Secure Connect";
if(detected_model != "unknown"){
	name += " on " + detected_model;
}
cpe1 = build_cpe( value: tolower( detected_version ), exp: "^([0-9R.]+)", base: "cpe:/a:pulsesecure:pulse_connect_secure:" );
cpe2 = build_cpe( value: tolower( detected_version ), exp: "^([0-9R.]+)", base: "cpe:/a:juniper:pulse_connect_secure:" );
if(!cpe1){
	cpe1 = "cpe:/a:pulsesecure:pulse_connect_secure";
	cpe2 = "cpe:/a:juniper:pulse_connect_secure";
}
os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Pulse Connect Secure Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "pulsesecure/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: cpe1, location: location, port: port, service: "www" );
		register_product( cpe: cpe2, location: location, port: port, service: "www" );
	}
}
if(snmp_ports = get_kb_list( "pulsesecure/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "pulsesecure/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  SNMP Banner:  " + concluded + "\n";
		}
		register_product( cpe: cpe1, location: location, port: port, service: "snmp", proto: "udp" );
		register_product( cpe: cpe2, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: name, version: detected_version, install: location, cpe: cpe1 );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

