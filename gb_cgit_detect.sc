if(description){
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_oid( "1.3.6.1.4.1.25623.1.0.103719" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-05-28 12:52:27 +0200 (Tue, 28 May 2013)" );
	script_name( "cgit Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Cgit.

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/cgit", "/git", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(IsMatchRegexp( buf, "<meta name=[\"\']generator[\"\'] content=[\"\']cgit" ) && ContainsString( buf, "repository" )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "<meta name=[\"\']generator[\"\'] content=[\"\']cgit v([^\"\']+)[\"\']/?>", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		set_kb_item( name: NASLString( "www/", port, "/cgit" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "cgit/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:lars_hjemli:cgit:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:lars_hjemli:cgit";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Cgit", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		lines = split( buf );
		for line in lines {
			repo = eregmatch( pattern: "href='/[^>]+/'>([^<]+)</a>", string: line );
			if(!isnull( repo[1] )){
				set_kb_item( name: "cgit/repos", value: repo[1] );
			}
		}
		exit( 0 );
	}
}
exit( 0 );

