if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114000" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-05-29 13:16:48 +0200 (Wed, 29 May 2019)" );
	script_name( "Q-See IP Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  Q-See's IP camera software.

  This script sends an HTTP GET request and tries to ensure the presence of
  the Q-See IP camera web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/web_caps/webCapsConfig";
res = http_get_cache( port: port, item: url );
if(!res){
	exit( 0 );
}
match = eregmatch( string: res, pattern: "\"vendor\"\\s*:\\s*\"QSee\"", icase: TRUE );
if(!match){
	exit( 0 );
}
concl = match[0];
version = "unknown";
model = "unknown";
set_kb_item( name: "qsee/ip_camera/detected", value: TRUE );
ver = eregmatch( pattern: "\"WebVersion\"\\s*:\\s*\"([^\"]+)\"", string: res );
if(!isnull( ver[1] )){
	version = NASLString( ver[1] );
	concl += "\n" + ver[0];
}
mod = eregmatch( pattern: "\"deviceType\"\\s*:\\s*\"([^\"]+)\"", string: res );
if(!isnull( mod[1] )){
	model = NASLString( mod[1] );
	concl += "\n" + mod[0];
}
if( model != "unknown" ){
	cpe_model = str_replace( string: tolower( model ), find: " ", replace: "_" );
	hw_cpe = "cpe:/h:qsee:ip_camera_" + cpe_model + ":";
	os_cpe = "cpe:/o:qsee:ip_camera_" + cpe_model + "_firmware";
	os_name = "Q-See IP Camera " + model + " Firmware";
	extra_info = "Detected model: " + model;
}
else {
	hw_cpe = "cpe:/h:qsee:ip_camera_unknown_model:";
	os_cpe = "cpe:/o:qsee:ip_camera_unknown_model_firmware";
	os_name = "Q-See IP Camera Unknown Model Firmware";
}
conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Q-See IP Camera Remote Detection", runs_key: "unixoide" );
register_and_report_cpe( app: "Q-See IP Camera", ver: version, concluded: concl, base: hw_cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl, extra: extra_info );
exit( 0 );

