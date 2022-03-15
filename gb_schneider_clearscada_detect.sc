if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141106" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-05-17 15:22:07 +0700 (Thu, 17 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Schneider Electric ClearSCADA Detection" );
	script_tag( name: "summary", value: "Detection of Schneider Electric ClearSCADA.

  The script sends a connection request to the server and attempts to detect Schneider Electric ClearSCADA and to
  extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://software.schneider-electric.com/products/clearscada/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "title=\"ClearSCADA Home\"" ) && ContainsString( res, "CurUser" )){
	version = "unknown";
	vers = eregmatch( pattern: "Server: ClearSCADA/([0-9.]+)", string: res );
	if( !isnull( vers[1] ) ) {
		version = vers[1];
	}
	else {
		url = "/alarms/";
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "cab#Version=([0-9,]+)", string: res );
		if(!isnull( vers[1] )){
			version = str_replace( string: vers[1], find: ",", replace: "." );
			concUrl = url;
		}
	}
	set_kb_item( name: "schneider_clearscada/installed", value: TRUE );
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", desc: "Schneider Electric ClearSCADA Detection", runs_key: "windows" );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:schneider-electric:clearscada:" );
	if(!cpe){
		cpe = "cpe:/a:schneider-electric:clearscada";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Schneider Electric ClearSCADA", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

