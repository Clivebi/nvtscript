if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103830" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-11-13 18:05:10 +0100 (Wed, 13 Nov 2013)" );
	script_name( "Webuzo Detection (HTTP)" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2002, 2004 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 2004 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/index.php?act=login";
buf = http_get_cache( item: url, port: port );
if(ContainsString( buf, "<title>Login" ) && ContainsString( buf, "Powered By Webuzo" ) && ContainsString( buf, "SOFTCookies" )){
	set_kb_item( name: "webuzo/installed", value: TRUE );
	vers = "unknown";
	version = eregmatch( pattern: "Powered By Webuzo ([0-9.]+)", string: buf );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:softaculous:webuzo:" );
	if(!cpe){
		cpe = "cpe:/a:softaculous:webuzo";
	}
	register_product( cpe: cpe, location: url, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Webuzo", version: vers, install: url, cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

