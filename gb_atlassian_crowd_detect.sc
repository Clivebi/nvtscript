if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106374" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Atlassian Crowd Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.atlassian.com/software/crowd" );
	script_tag( name: "summary", value: "Detection of Atlassian Crowd.

  The script sends a connection request to the server and attempts to detect the presence of Atlassian Crowd and to
  extract its version" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
req = http_get( port: port, item: "/crowd/console/login.action" );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "<title>Atlassian Crowd - Login" ) && ContainsString( res, "/crowd/console/j_security_check" ) ) || ( ContainsString( res, "Atlassian<" ) && ContainsString( res, "Crowd Console<" ) )){
	version = "unknown";
	install = "/";
	vers = eregmatch( pattern: "Version:&nbsp;([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "atlassian_crowd/version", value: version );
	}
	set_kb_item( name: "atlassian_crowd/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:crowd:" );
	if(!cpe){
		cpe = "cpe:/a:atlassian:crowd";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Atlassian Crowd", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
}
exit( 0 );

