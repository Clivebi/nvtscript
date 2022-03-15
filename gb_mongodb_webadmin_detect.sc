if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100748" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-06 15:09:20 +0200 (Fri, 06 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "MongoDB Web Admin Detection" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 28017 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_xref( name: "URL", value: "http://www.mongodb.org/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 28017 );
banner = http_get_remote_headers( port: port );
if(!banner || ContainsString( banner, "Server:" )){
	exit( 0 );
}
buf = http_get_cache( item: "/", port: port );
if(( IsMatchRegexp( buf, "<title>[^<]*mongod[^<]*</title>" ) && ContainsString( buf, "buildInfo" ) ) || ( ContainsString( buf, "unauthorized db:admin lock type" ) )){
	set_kb_item( name: "mongodb/webadmin/port", value: port );
	vers = "unknown";
	install = "/";
	if(ContainsString( buf, "db version" )){
		version = eregmatch( pattern: "db version v([^\n, ]+)", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
			set_kb_item( name: "mongodb/webadmin/version", value: vers );
		}
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:mongodb:mongodb:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:mongodb:mongodb";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( port: port, data: build_detection_report( app: "MongoDB Web Admin", version: vers, install: install, cpe: cpe, concluded: version[0] ) );
}
exit( 0 );

