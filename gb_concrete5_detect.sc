if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106757" );
	script_version( "2021-03-29T03:16:01+0000" );
	script_tag( name: "last_modification", value: "2021-03-29 03:16:01 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-04-18 16:13:12 +0200 (Tue, 18 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Concrete5 / Concrete CMS Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Concrete CMS (formerly Concrete5 CMS)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.concrete5.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/index.php/login" );
	if(ContainsString( res, "content=\"concrete5" ) && ContainsString( res, "CCM_IMAGE_PATH" ) && ContainsString( res, "CCM_REL" )){
		version = "unknown";
		vers = eregmatch( pattern: "concrete5 - ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "concrete5/version", value: version );
		}
		set_kb_item( name: "concrete5/installed", value: TRUE );
		cpe1 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:portlandlabs:concrete_cms:" );
		cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:concrete5:concrete5:" );
		if(!cpe1){
			cpe1 = "cpe:/a:portlandlabs:concrete_cms";
			cpe2 = "cpe:/a:concrete5:concrete5";
		}
		register_product( cpe: cpe1, location: install, port: port, service: "www" );
		register_product( cpe: cpe2, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Concrete5 / Concrete CMS", version: version, install: install, cpe: cpe1, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

