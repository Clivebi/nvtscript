if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114095" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-04-30 14:52:46 +0200 (Tue, 30 Apr 2019)" );
	script_name( "Zavio IP Cameras Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  Zavio IP Cameras.

  This script sends an HTTP GET request and tries to ensure the presence of
  a Zavio IP Camera." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/profile";
res = http_get_cache( port: port, item: url );
if(IsMatchRegexp( res, "initProdNbr=\"([^\"]+)\";" ) && ( IsMatchRegexp( res, "BrandCopyright=\"Zavio\\s*\";" ) || IsMatchRegexp( res, "initBrand=\"Zavio\\s*\";" ) )){
	version = "unknown";
	model = "unknown";
	mod = eregmatch( pattern: "initProdNbr=\"([^\"]+)\";", string: res );
	if(!isnull( mod[1] )){
		model = NASLString( mod[1] );
	}
	set_kb_item( name: "zavio/ip_camera/detected", value: TRUE );
	if( model != "unknown" ){
		cpe_model = str_replace( string: tolower( model ), find: " ", replace: "_" );
		hw_cpe = "cpe:/h:zavio:ip_camera_" + cpe_model + ":";
		os_cpe = "cpe:/o:zavio:ip_camera_" + cpe_model + "_firmware";
		os_name = "Zavio IP Camera " + model + " Firmware";
		extra_info = "Detected model: " + model;
	}
	else {
		hw_cpe = "cpe:/h:zavio:ip_camera_unknown_model:";
		os_cpe = "cpe:/o:zavio:ip_camera_unknown_model_firmware";
		os_name = "Zavio IP Camera Unknown Model Firmware";
	}
	os_register_and_report( os: os_name, cpe: os_cpe, desc: "Zavio IP Cameras Remote Detection", runs_key: "unixoide" );
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Zavio IP Camera", ver: version, base: hw_cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl, extra: extra_info );
}
exit( 0 );

