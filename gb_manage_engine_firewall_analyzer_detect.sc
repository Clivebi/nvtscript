if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811533" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-07-19 13:54:26 +0530 (Wed, 19 Jul 2017)" );
	script_name( "ManageEngine Firewall Analyzer Detection" );
	script_tag( name: "summary", value: "Detection of ManageEngine Firewall Analyzer.

The script sends a connection request to the server and attempts to detect ManageEngine Firewall Analyzer and to
extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8500 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
http_port = http_get_port( default: 8500 );
url = "/apiclient/ember/Login.jsp";
buf = http_get_cache( item: url, port: http_port );
if(ContainsString( buf, "Firewall Analyzer" ) && IsMatchRegexp( buf, ">Firewall Log Analytics Software from ManageEngine.*Copyright.*ZOHO Corp" )){
	version = "unknown";
	set_kb_item( name: "me_firewall_analyzer/installed", value: TRUE );
	vers = eregmatch( string: buf, pattern: "Firewall Analyzer<span>v ([0-9.]+)</span>", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:zohocorp:manageengine_firewall_analyzer:" );
	if(!cpe){
		cpe = "cpe:/a:zohocorp:manageengine_firewall_analyzer";
	}
	register_product( cpe: cpe, location: "/", port: http_port, service: "www" );
	log_message( data: build_detection_report( app: "ManageEngine Firewall Analyzer", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: http_port );
	exit( 0 );
}
exit( 0 );

