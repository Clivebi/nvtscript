if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100196" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "A A S Application Access Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 6262 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of A A S Application Access Server." );
	script_xref( name: "URL", value: "http://www.klinzmann.name/a-a-s/index_en.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 6262 );
buf = http_get_cache( item: "/", port: port );
if(egrep( pattern: "Server: AAS", string: buf, icase: TRUE )){
	vers = NASLString( "unknown" );
	version = eregmatch( string: buf, pattern: "Server: AAS/([0-9.]+)", icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "aas/detected", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:klinzmann:application_access_server:" );
	if(!cpe){
		cpe = "cpe:/a:klinzmann:application_access_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "AAS Application Access Server", version: vers, install: "/", cpe: cpe, concluded: version[1] ), port: port );
}
exit( 0 );

