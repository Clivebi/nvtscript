if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143323" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-01-08 07:50:11 +0000 (Wed, 08 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ruckus Unleashed Detection" );
	script_tag( name: "summary", value: "Detection of Ruckus Unleashed.

  The script sends a connection request to the server and attempts to detect Ruckus Unleashed devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.ruckuswireless.com/products/system-management-control/unleashed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/admin/login.jsp" );
if(ContainsString( res, "<title>Unleashed Login</title>" ) && ContainsString( res, "ruckus_logo" )){
	version = "unknown";
	set_kb_item( name: "ruckus/unleashed/detected", value: TRUE );
	app_cpe = "cpe:/a:ruckuswireless:unleashed_firmware";
	os_cpe = "cpe:/o:ruckuswireless:unleashed_firmware";
	hw_cpe = "cpe:/h:ruckuswireless:unleashed";
	os_register_and_report( os: "Ruckus Unleashed Firmware", cpe: os_cpe, desc: "Ruckus Unleashed Detection", runs_key: "unixoide" );
	register_product( cpe: app_cpe, location: "/", port: port, service: "www" );
	register_product( cpe: os_cpe, location: "/", port: port, service: "www" );
	register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
	report = log_message( data: build_detection_report( app: "Ruckus Unleashed", version: version, install: "/", cpe: app_cpe ), port: port );
	exit( 0 );
}
exit( 0 );

