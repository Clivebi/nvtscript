if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140832" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-01 14:35:48 +0700 (Thu, 01 Mar 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Parallels Remote Application Server (RAS) Detection" );
	script_tag( name: "summary", value: "Detection of Parallels Remote Application Server (RAS).

The script sends a connection request to the server and attempts to detect Parallels RAS and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.parallels.com/products/ras/remote-application-server/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/2XWebPortal/logon.aspx" );
if(( ContainsString( res, "RAS Web Portal" ) && ContainsString( res, "Parallels Client installed" ) ) || ( ContainsString( res, "2X RAS Portal" ) && ContainsString( res, "2X RDP Client installed" ) )){
	version = "unknown";
	vers = eregmatch( pattern: "\\.js\\?v=([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "parallels_ras/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:parallels:remote_application_server:" );
	if(!cpe){
		cpe = "cpe:/a:parallels:remote_application_server";
	}
	register_product( cpe: cpe, location: "/2XWebPortal", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Parallels RAS", version: version, install: "/2XWebPortal", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

