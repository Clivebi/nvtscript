if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112337" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-25 13:49:11 +0200 (Wed, 25 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Trendnet Internet Camera Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Trendnet Internet Camera devices." );
	script_xref( name: "URL", value: "https://www.trendnet.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
CPE = "cpe:/h:trendnet:ip_camera:";
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && IsMatchRegexp( banner, "www-authenticate:[ ]?basic[ ]?realm=\"netcam" )){
	set_kb_item( name: "trendnet/ip_camera/detected", value: TRUE );
	set_kb_item( name: "trendnet/ip_camera/http_port", value: port );
	version = "unknown";
	register_and_report_cpe( app: "Trendnet IP Camera", ver: version, base: CPE, expr: "([^0-9.]+)", insloc: "/", regPort: port );
	exit( 0 );
}
exit( 0 );

