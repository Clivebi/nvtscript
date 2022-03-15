if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141772" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-12-12 13:23:36 +0700 (Wed, 12 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Rockwell Automation MicroLogix Detection Consolidation" );
	script_tag( name: "summary", value: "Reports the Rockwell Automation MicroLogix model and firmware version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_rockwell_micrologix_http_detect.sc", "gb_rockwell_micrologix_ethernetip_detect.sc" );
	script_mandatory_keys( "rockwell_micrologix/detected" );
	script_xref( name: "URL", value: "http://ab.rockwellautomation.com/Programmable-Controllers/MicroLogix-Systems" );
	;
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "rockwell_micrologix/detected" )){
	exit( 0 );
}
detected_model = "unknown";
detected_fw_version = "unknown";
detected_series = "";
for source in make_list( "http",
	 "ethernetip" ) {
	fw_version_list = get_kb_list( "rockwell_micrologix/" + source + "/*/fw_version" );
	for fw_version in fw_version_list {
		if(fw_version && detected_fw_version == "unknown"){
			detected_fw_version = fw_version;
			set_kb_item( name: "rockwell_micrologix/fw_version", value: fw_version );
		}
	}
	model_list = get_kb_list( "rockwell_micrologix/" + source + "/*/model" );
	for model in model_list {
		if(model && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "rockwell_micrologix/model", value: model );
		}
	}
	ser_list = get_kb_list( "rockwell_micrologix/" + source + "/*/series" );
	for series in ser_list {
		if(series && detected_series == ""){
			detected_series = series;
			set_kb_item( name: "rockwell_micrologix/series", value: series );
		}
	}
}
app_name = "Rockwell Automation MicroLogix Controller ";
if( detected_model != "unknown" ){
	app_name += detected_model;
	mod = eregmatch( pattern: "([^ ]+)", string: detected_model );
	app_cpe = "cpe:/a:rockwellautomation:" + tolower( mod[1] );
	os_cpe = "cpe:/o:rockwellautomation:" + tolower( mod[1] ) + "_firmware";
	hw_cpe = "cpe:/h:rockwellautomation:" + tolower( mod[1] );
}
else {
	app_cpe = "cpe:/a:rockwellautomation:micrologix";
	os_cpe = "cpe:/o:rockwellautomation:micrologix_firmware";
	hw_cpe = "cpe:/h:rockwellautomation:micrologix";
}
if(detected_fw_version != "unknown"){
	app_cpe += ":" + detected_fw_version;
	os_cpe += ":" + detected_fw_version;
}
if(detected_series != ""){
	app_name += " Series " + detected_series;
}
os_register_and_report( os: "Rockwell Automation MicroLogix Controller Firmware", cpe: os_cpe, desc: "Rockwell Automation MicroLogix Detection Consolidation", runs_key: "unixoide" );
location = "/";
if(http_ports = get_kb_list( "rockwell_micrologix/http/port" )){
	for port in http_ports {
		mac = get_kb_item( "rockwell_micrologix/http/" + port + "/mac" );
		if(mac){
			macaddr = "MAC address:    " + mac;
		}
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
		register_product( cpe: os_cpe, location: location, port: port, service: "www" );
		register_product( cpe: app_cpe, location: location, port: port, service: "www" );
	}
}
if(ether_ports = get_kb_list( "rockwell_micrologix/ethernetip/port" )){
	for port in ether_ports {
		if(ether_protos = get_kb_list( "rockwell_micrologix/ethernetip/" + port + "/proto" )){
			for proto in ether_protos {
				extra += "EtherNet/IP on port " + port + "/" + proto + "\n";
				register_product( cpe: hw_cpe, location: location, port: port, service: "ethernetip", proto: proto );
				register_product( cpe: os_cpe, location: location, port: port, service: "ethernetip", proto: proto );
				register_product( cpe: app_cpe, location: location, port: port, service: "ethernetip", proto: proto );
			}
		}
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

