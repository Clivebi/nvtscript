if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141122" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-30 11:14:38 +0700 (Wed, 30 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine ADAudit Plus Detection" );
	script_tag( name: "summary", value: "Detection of ManageEngine ADAudit Plus.

The script sends a connection request to the server and attempts to detect ManageEngine ADAudit Plus and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/active-directory-audit/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8081 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>ADAudit Plus</title>" ) && ContainsString( res, "ADAPLogin.js" )){
	version = "unknown";
	vers = eregmatch( pattern: "\\.(css|js)?\\?v=([0-9]+)", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
	set_kb_item( name: "me_adauitplus/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9]+)", base: "cpe:/a:manageengine:adaudit_plus:" );
	if(!cpe){
		cpe = "cpe:/a:manageengine:adaudit_plus";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ManageEngine ADAudit Plus", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

