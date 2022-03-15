if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805717" );
	script_version( "2021-09-23T03:58:52+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-23 03:58:52 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-07-08 18:54:23 +0530 (Wed, 08 Jul 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine Desktop Central Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of ManageEngine Desktop Central." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8020 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/desktop-central/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8020 );
res = http_get_cache( port: port, item: "/configurations.do" );
if(ContainsString( res, ">ManageEngine Desktop Central" )){
	version = "unknown";
	vers = eregmatch( pattern: "id=\"buildNum\" value=\"([0-9]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		display( strlen( version ) );
		if( strlen( version ) >= 6 ) {
			version = substr( version, 0, 1 ) + "." + version[2] + "." + substr( version, 3 );
		}
		else {
			version = version[0] + "." + version[1] + "." + substr( version, 2 );
		}
	}
	set_kb_item( name: "manageengine/desktop_central/detected", value: TRUE );
	set_kb_item( name: "manageengine/desktop_central/http/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:zohocorp:manageengine_desktop_central:" );
	if(!cpe){
		cpe = "cpe:/a:zohocorp:manageengine_desktop_central";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ManageEngine Desktop Central", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

