if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144459" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-08-25 08:08:42 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei iBMC Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of Huawei iBMC detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_huawei_ibmc_upnp_detect.sc", "gb_huawei_ibmc_http_detect.sc" );
	script_mandatory_keys( "huawei/ibmc/detected" );
	script_xref( name: "URL", value: "https://e.huawei.com/en/products/servers/accessories/ibmc" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!get_kb_item( "huawei/ibmc/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_model = "unknown";
location = "/";
for source in make_list( "upnp",
	 "http" ) {
	version_list = get_kb_list( "huawei/ibmc/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
	model_list = get_kb_list( "huawei/ibmc/" + source + "/*/model" );
	for model in model_list {
		if(model != "unknown" && detected_model == "unknown"){
			detected_model = model;
			set_kb_item( name: "huawei/server/model", value: detected_model );
			break;
		}
	}
}
if( detected_model != "unknown" ) {
	os_name = "Huawei iBMC Firmware on " + detected_model;
}
else {
	os_name = "Huawei iBMC Firmware";
}
cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:huawei:ibmc_firmware:" );
if(!cpe){
	cpe = "cpe:/o:huawei:ibmc_firmware";
}
os_register_and_report( os: os_name, cpe: cpe, desc: "Huawei iBMC Detection Consolidation", runs_key: "unixoide" );
if(http_ports = get_kb_list( "huawei/ibmc/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "huawei/ibmc/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		concUrl = get_kb_item( "huawei/ibmc/http/" + port + "/concludedUrl" );
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(upnp_ports = get_kb_list( "huawei/ibmc/upnp/port" )){
	for port in upnp_ports {
		extra += "UPnP on port " + port + "/udp\n";
		concluded = get_kb_item( "huawei/ibmc/upnp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "upnp", proto: "udp" );
	}
}
report = build_detection_report( app: os_name, version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

