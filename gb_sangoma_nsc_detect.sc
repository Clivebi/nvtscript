if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112183" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-01-11 12:07:00 +0100 (Thu, 11 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sangoma NetBorder/Vega Session Controller Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.sangoma.com/products/sbc/" );
	script_tag( name: "summary", value: "This script sends an HTTP GET request to figure out whether a
  web-based service of Sangoma Session Border Controller (SBC) is running on the target host, and,
  if so, which version is installed." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
hw_cpe = "cpe:/h:sangoma:netborder%2fvega_session";
hw_name = "Sangoma NetBorder/Vega Session Controller";
os_cpe = "cpe:/o:sangoma:netborder%2fvega_session_firmware";
os_name = hw_name + " Firmware";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	installed = FALSE;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in make_list( "/",
		 "/index.php" ) {
		url = dir + file;
		res = http_get_cache( item: url, port: port );
		if(ContainsString( res, "Session Controller" ) && ContainsString( res, "SNG_logo.png\" alt=\"Sangoma\"" )){
			installed = TRUE;
			break;
		}
	}
	if(installed){
		set_kb_item( name: "sangoma/nsc/detected", value: TRUE );
		version = "unknown";
		os_register_and_report( os: os_name, cpe: os_cpe, desc: "Sangoma NetBorder/Vega Session Controller Detection", runs_key: "unixoide" );
		register_product( cpe: os_cpe, location: install, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
		report = build_detection_report( app: os_name, version: version, install: install, cpe: os_cpe );
		report += "\n\n";
		report += build_detection_report( app: hw_name, install: install, cpe: hw_cpe, skip_version: TRUE );
		log_message( port: port, data: report );
	}
}
exit( 0 );

