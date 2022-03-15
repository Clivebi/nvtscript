if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800417" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "LiveZilla Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of LiveZilla.

  The script sends a request to access the 'index.php' and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/LiveZilla", "/livezilla", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "<title>LiveZilla Server Page</title>" ) || ContainsString( res, "<META NAME=\"generator\" CONTENT=\"LiveZilla GmbH" ) || ContainsString( res, "lz_chat_data_box()" ) || ContainsString( res, "LiveZilla GmbH" )){
		version = "unknown";
		ver = eregmatch( pattern: ">[Vv]ersion ([0-9.]+)", string: res );
		if(ver[1] != NULL){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "LiveZilla/installed", value: TRUE );
		set_kb_item( name: "www/" + port + "/LiveZilla", value: tmp_version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:livezilla:livezilla:" );
		if(!cpe){
			cpe = "cpe:/a:livezilla:livezilla";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LiveZilla", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

