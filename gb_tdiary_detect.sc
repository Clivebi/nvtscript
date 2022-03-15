if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800991" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "tDiary Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the installed version of tDiary." );
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
for path in nasl_make_list_unique( "/tdiary", "/", http_cgi_dirs( port: port ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	res = http_get_cache( item: path + "/index.rb", port: port );
	if(ContainsString( res, ">tDiary<" )){
		version = "unknown";
		diaryVer = eregmatch( pattern: "tDiary.* version ([0-9.]+)<", string: res );
		if(!isnull( diaryVer[1] )){
			version = diaryVer[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/tdiary", value: tmp_version );
		set_kb_item( name: "tdiary/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tdiary:tdiary:" );
		if(!cpe){
			cpe = "cpe:/a:tdiary:tdiary";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "tDiary", version: version, install: install, cpe: cpe, concluded: diaryVer[0] ), port: port );
	}
}
exit( 0 );

