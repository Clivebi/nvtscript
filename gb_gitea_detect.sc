if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141676" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-13 11:18:05 +0700 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Gitea Detection" );
	script_tag( name: "summary", value: "Detection of Gitea.

The script sends a connection request to the server and attempts to detect Gitea and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3000, 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://gitea.io/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 3000 );
res = http_get_cache( port: port, item: "/user/login" );
if(ContainsString( res, "Gitea - Git with a cup of tea" ) && ContainsString( res, "i_like_gitea" )){
	version = "unknown";
	vers = eregmatch( pattern: "Gitea Version: ([^ ]+)", string: res );
	if(!isnull( vers[1] )){
		version = str_replace( string: vers[1], find: "&#43;", replace: "." );
		version = str_replace( string: version, find: "-", replace: "." );
	}
	set_kb_item( name: "gitea/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:gitea:gitea:" );
	if(!cpe){
		cpe = "cpe:/a:gitea:gitea";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Gitea", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	goVersion = "unknown";
	goVer = eregmatch( pattern: "version\">Go([0-9.]+)", string: res );
	if(!isnull( goVer[1] )){
		goVersion = goVer[1];
	}
	gocpe = build_cpe( value: goVersion, exp: "^([0-9.]+)", base: "cpe:/a:golang:go:" );
	if(!gocpe){
		gocpe = "cpe:/a:golang:go";
	}
	register_product( cpe: gocpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Go Programming Language", version: goVersion, install: "/", cpe: gocpe, concluded: goVer[0] ), port: port );
	exit( 0 );
}
exit( 0 );

