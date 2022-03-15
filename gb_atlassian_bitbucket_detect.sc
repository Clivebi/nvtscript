if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106759" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-18 10:53:03 +0200 (Tue, 18 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Atlassian Bitbucket Detection" );
	script_tag( name: "summary", value: "Detection of Atlassian Bitbucket.

The script sends a connection request to the server and attempts to detect Atlassian Bitbucket and to extract
the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.atlassian.com/software/bitbucket" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/bitbucket", "/stash", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/login" );
	if(ContainsString( res, ">Atlassian Bitbucket<" ) && ContainsString( res, "bitbucket.page.login" ) && ContainsString( res, "com.atlassian.bitbucket" )){
		version = "unknown";
		vers = eregmatch( pattern: "id=\"product-version\".* v([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "atlassian_bitbucket/version", value: version );
		}
		set_kb_item( name: "atlassian_bitbucket/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:bitbucket:" );
		if(!cpe){
			cpe = "cpe:/a:atlassian:bitbucket";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Atlassian Bitbucket", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

