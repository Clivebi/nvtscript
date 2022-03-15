if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107114" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-28 13:26:09 +0700 (Wed, 28 Dec 2016)" );
	script_name( "Horos Web Portal Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3333 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Horos Web Portal" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 3333 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Horos Web Portal</title>" ) || IsMatchRegexp( buf, "H...o...r...o...s... ...W...e...b... ...P...o...r...t...a...l" ) || ContainsString( buf, "Service provided by <a href=\"http://www.horosproject.org\"" ) )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "Horos Web Portal = \"([0-9].[0-9].[0-9])\"", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		set_kb_item( name: "www/" + port + "/horos", value: vers + " under " + install );
		set_kb_item( name: "horos/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:horos:horos:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:horos:horos";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Horos Web Portal", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
	}
}
exit( 0 );

