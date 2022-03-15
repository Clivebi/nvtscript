if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802428" );
	script_version( "2020-11-12T10:09:08+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-04-16 13:02:43 +0530 (Mon, 16 Apr 2012)" );
	script_name( "AppServ Open Project Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.appservnetwork.com/?appserv" );
	script_tag( name: "summary", value: "Detection of AppServ Open Project, an open source web
  server.

  The script sends a connection request to the web server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, "title>AppServ Open Project" ) && ContainsString( res, ">About AppServ" )){
	appVer = eregmatch( pattern: "AppServ Version ([0-9.]+)", string: res );
	if(appVer[1] != NULL){
		set_kb_item( name: "www/" + port + "/AppServ", value: appVer[1] );
	}
	set_kb_item( name: "AppServ/installed", value: TRUE );
	cpe = build_cpe( value: appVer[1], exp: "^([0-9.]+)", base: " cpe:/a:appserv_open_project:appserv:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:appserv_open_project:appserv";
	}
	location = NASLString( port, "/http" );
	register_product( cpe: cpe, location: location, port: port, service: "www" );
	log_message( data: "Detected AppServ Open Project version: " + appVer[1] + "\nLocation: " + location + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + appVer[max_index( appVer ) - 1] );
}
exit( 0 );

