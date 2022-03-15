if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100405" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ZABBIX Web Interface Detection" );
	script_tag( name: "summary", value: "Detects the installed version of ZABBIX
  Web Interface.

  This script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "zabbix_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
zbPort = http_get_port( default: 80 );
if(!http_can_host_php( port: zbPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/zabbix", "/monitoring", http_cgi_dirs( port: zbPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php" );
	buf = http_get_cache( item: url, port: zbPort );
	if(!buf){
		continue;
	}
	if(( egrep( pattern: "index.php\\?login=1", string: buf, icase: TRUE ) && egrep( pattern: "SIA Zabbix", string: buf ) ) || ( IsMatchRegexp( buf, "<title>(.*)?Zabbix</title>" ) && ContainsString( buf, "Zabbix SIA" ) )){
		zbVer = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "Zabbix([&nbsp; ]+)([0-9.]+)", icase: TRUE );
		if( !isnull( version[2] ) ){
			zbVer = chomp( version[2] );
		}
		else {
			version = eregmatch( string: buf, pattern: "jsLoader.php\\?ver=([0-9.]+)" );
			if(!isnull( version[1] )){
				zbVer = version[1];
			}
		}
		set_kb_item( name: NASLString( "www/", zbPort, "/zabbix_client" ), value: NASLString( zbVer, " under ", install ) );
		set_kb_item( name: "Zabbix/installed", value: TRUE );
		set_kb_item( name: "Zabbix/Web/installed", value: TRUE );
		cpe = build_cpe( value: zbVer, exp: "^([0-9.]+)", base: "cpe:/a:zabbix:zabbix:" );
		if(!cpe){
			cpe = "cpe:/a:zabbix:zabbix";
		}
		register_product( cpe: cpe, location: install, port: zbPort, service: "www" );
		log_message( data: build_detection_report( app: "Zabbix", version: zbVer, install: install, cpe: cpe, concluded: version[0] ), port: zbPort );
	}
}
exit( 0 );

