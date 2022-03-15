require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145200" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-01-20 06:52:37 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Loxone Miniserver Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Loxone Miniserver device detection." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_loxone_miniserver_http_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_loxone_miniserver_upnp_detect.sc", "gsf/gb_loxone_miniserver_knx_detect.sc" );
	}
	script_mandatory_keys( "loxone/miniserver/detected" );
	script_xref( name: "URL", value: "https://www.loxone.com/enen/products/miniserver-extensions/" );
	exit( 0 );
}
if(!get_kb_item( "loxone/miniserver/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "http",
	 "upnp",
	 "knx" ) {
	version_list = get_kb_list( "loxone/miniserver/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:loxone:miniserver_firmware:" );
if(!os_cpe){
	os_cpe = "cpe:/o:loxone:miniserver_firmware";
}
hw_cpe = "cpe:/h:loxone:miniserver";
os_register_and_report( os: "Loxone Miniserver Firmware", cpe: os_cpe, desc: "Loxone Miniserver Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "loxone/miniserver/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "loxone/miniserver/http/" + port + "/concluded" );
		concUrl = get_kb_item( "loxone/miniserver/http/" + port + "/concludedUrl" );
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
if(upnp_ports = get_kb_list( "loxone/miniserver/upnp/port" )){
	for port in upnp_ports {
		extra += "UPNP on port " + port + "/udp\n";
		concUrl = get_kb_item( "loxone/miniserver/upnp/" + port + "/concludedUrl" );
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "upnp", proto: "udp" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "upnp", proto: "udp" );
	}
}
if(knx_ports = get_kb_list( "loxone/miniserver/knx/port" )){
	for port in knx_ports {
		extra += "KNX on port " + port + "/udp\n";
		concluded = get_kb_item( "loxone/miniserver/knx/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: os_cpe, location: location, port: port, service: "knx", proto: "udp" );
		register_product( cpe: hw_cpe, location: location, port: port, service: "knx", proto: "udp" );
	}
}
report = build_detection_report( app: "Loxone Miniserver Firmware", version: detected_version, install: location, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: "Loxone Miniserver", skip_version: TRUE, install: location, cpe: hw_cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

