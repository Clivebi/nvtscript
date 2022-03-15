if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100215" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PRTG Traffic Grapher Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "PRTG Traffic Grapher, a Windows software for monitoring and
  classifying bandwidth traffic usage is running at this host." );
	script_xref( name: "URL", value: "http://www.paessler.com/prtg6" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/login.htm";
buf = http_get_cache( item: url, port: port );
if(!buf){
	exit( 0 );
}
if(egrep( pattern: "PRTG Traffic Grapher V[0-9.]+", string: buf, icase: TRUE ) && egrep( pattern: "sensorlist.htm", string: buf, icase: TRUE )){
	vers = NASLString( "unknown" );
	install = "/";
	version = eregmatch( string: buf, pattern: "PRTG Traffic Grapher V([0-9.]+)", icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "prtgtrafficgrapher/detected", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:paessler:prtg_traffic_grapher:" );
	if(!cpe){
		cpe = "cpe:/a:paessler:prtg_traffic_grapher";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "PRTG Traffic Grapher", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

