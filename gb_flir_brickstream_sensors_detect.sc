if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812369" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-02 16:27:00 +0530 (Tue, 02 Jan 2018)" );
	script_name( "Flir Brickstream Sensors Detection" );
	script_tag( name: "summary", value: "Detection of running version of
  Flir Brickstream Sensors.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
flirPort = http_get_port( default: 80 );
res = http_get_cache( port: flirPort, item: "/" );
if(IsMatchRegexp( res, ">Brickstream.*Configuration<" ) && ContainsString( res, ">Use this page to configure initial settings for the Brickstream" )){
	flirVer = "Unknown";
	sndReq = http_get( item: "/help.html", port: flirPort );
	res = http_keepalive_send_recv( port: flirPort, data: sndReq );
	vers = eregmatch( pattern: "id=\"BS_COUNTING_REL\" value=\"([0-9.]+)\"", string: res );
	if(vers[1]){
		flirVer = vers[1];
	}
	set_kb_item( name: "Flir/Brickstream/Installed", value: TRUE );
	cpe = build_cpe( value: flirVer, exp: "^([0-9.]+)", base: "cpe:/a:flir:brickstream_sensor:" );
	if(!cpe){
		cpe = "cpe:/a:flir:brickstream_sensor";
	}
	register_product( cpe: cpe, location: "/", port: flirPort, service: "www" );
	log_message( data: build_detection_report( app: "Flir Brickstream Sensor", version: flirVer, install: "/", cpe: cpe, concluded: flirVer ), port: flirPort );
	exit( 0 );
}
exit( 0 );

