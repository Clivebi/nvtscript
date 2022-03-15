if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140778" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-15 17:20:38 +0700 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine NetFlow Analyzer Detection" );
	script_tag( name: "summary", value: "Detection of ManageEngine NetFlow Analyzer.

The script sends a connection request to the server and attempts to detect ManageEngine NetFlow Analyzer and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/netflow/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/apiclient/ember/Login.jsp" );
if(ContainsString( res, "NetFlow Analyzer" ) && ContainsString( res, "'info'>The Complete Traffic Analytics Software" )){
	version = "unknown";
	vers = eregmatch( pattern: "NetFlow Analyzer<span>v ([0-9.]+)<", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "me_netflow_analyzer/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:zohocorp:manageengine_netflow_analyzer:" );
	if(!cpe){
		cpe = "cpe:/a:zohocorp:manageengine_netflow_analyzer";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ManageEngine NetFlow Analyzer", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

