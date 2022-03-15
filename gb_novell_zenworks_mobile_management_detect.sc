if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103733" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-10 12:53:22 +0200 (Mon, 10 Jun 2013)" );
	script_name( "Novell ZENworks Mobile Management Detection" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Novell ZENworks Mobile Management.

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/";
buf = http_get_cache( item: url, port: port );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "<title>ZENworks Mobile Management" ) && ( ContainsString( buf, "DUSAP.php" ) || ContainsString( buf, "loginUsernameField" ) )){
	install = "/";
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "<p id=\"version\">Version ([^<]+)</p>", icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: NASLString( "www/", port, "/zenworks_mobile_management" ), value: NASLString( vers, " under ", install ) );
	set_kb_item( name: "zenworks_mobile_management/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:novell:zenworks_mobile_management:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:novell:zenworks_mobile_management";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "ZENworks Mobile Management", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

