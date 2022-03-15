if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111071" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-15 19:00:00 +0100 (Tue, 15 Dec 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ComfortableMexicanSofa CMS Engine Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request
  to the server and attempts to extract the version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 3000 );
rootInstalled = 0;
for dir in nasl_make_list_unique( "/", "/cms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	if(rootInstalled){
		break;
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( buf, "/system/comfy/cms/files/" ) || ContainsString( buf, "/assets/comfy/" ) || ( ContainsString( buf, "comfy_admin_cms" ) && ContainsString( buf, "comfy/admin/cms/base" ) )){
		if(install == "/"){
			rootInstalled = 1;
		}
		version = "unknown";
		cpe = "cpe:/a:comfy:comfy";
		set_kb_item( name: "www/" + port + "/comfy", value: version );
		set_kb_item( name: "comfy/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "ComfortableMexicanSofa CMS Engine", version: version, install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );

