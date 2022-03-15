if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144537" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-09-09 05:30:36 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "D-Link DCS Device Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of D-Link DCS devices." );
	script_xref( name: "URL", value: "https://www.dlink.com/en/consumer/cameras" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!IsMatchRegexp( banner, "(Basic|Digest) realm=\"DCS-" )){
	exit( 0 );
}
version = "unknown";
model = "unknown";
set_kb_item( name: "Host/is_dlink_dcs_device", value: TRUE );
set_kb_item( name: "Host/is_dlink_device", value: TRUE );
mod = eregmatch( pattern: "Basic realm=\"(DCS\\-[^\"]+)\"", string: banner );
if(!isnull( mod[1] )){
	model = mod[1];
}
if( model != "unknown" ){
	os_name = "D-Link " + model + " Firmware";
	hw_name = "D-Link " + model;
	os_cpe = "cpe:/o:d-link:" + tolower( model ) + "_firmware";
	hw_cpe = "cpe:/h:d-link:" + tolower( model );
}
else {
	os_name = "D-Link DCS Unknown Model Firmware";
	hw_name = "D-Link DCS Unknown Model";
	os_cpe = "cpe:/o:d-link:dcs_firmware";
	hw_cpe = "cpe:/h:d-link:dcs";
}
os_register_and_report( os: os_name, cpe: os_cpe, banner_type: "D-Link DCS Device Login Page", port: port, desc: "D-Link DCS Device Detection (HTTP)", runs_key: "unixoide" );
register_product( cpe: os_cpe, location: "/", port: port, service: "www" );
register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
report = build_detection_report( app: os_name, version: version, install: "/", cpe: os_cpe );
report += "\n\n" + build_detection_report( app: hw_name, install: "/", cpe: hw_cpe, skip_version: TRUE );
log_message( port: port, data: report );
exit( 0 );

