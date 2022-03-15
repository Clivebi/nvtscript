if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105054" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-07-02 14:53:50 +0200 (Wed, 02 Jul 2014)" );
	script_name( "nas4free Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to detect nas4free from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/login.php";
buf = http_get_cache( item: url, port: port );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "The NAS4Free Project" ) && ContainsString( buf, "title=\"www.nas4free.org\"" ) && ContainsString( buf, "username" ) && ContainsString( buf, "password" )){
	install = "/";
	vers = "unknown";
	set_kb_item( name: NASLString( "www/", port, "/nas4free" ), value: NASLString( vers, " under ", install ) );
	set_kb_item( name: "nas4free/installed", value: TRUE );
	cpe = "cpe:/a:nas4free:nas4free";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "nas4free", version: vers, install: install, cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

