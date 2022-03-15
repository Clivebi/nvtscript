if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106414" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-28 11:22:24 +0700 (Mon, 28 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM BigFix Remote Control Detection" );
	script_tag( name: "summary", value: "Detection of IBM BigFix Remote Control

  The script sends a connection request to the server and attempts to detect the presence of IBM BigFix Remote
Control and to extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
req = http_get( port: port, item: "/trc/" );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "<title>IBM BigFix Remote Control" ) || IsMatchRegexp( res, "<title>(IBM|Tivoli) Endpoint Manager for Remote Control" ) ) && ContainsString( res, "action=\"/trc/logon.do" )){
	version = "unknown";
	vers = eregmatch( pattern: "s_about_version=\"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "ibm/bigfix_remote_control/version", value: version );
	}
	set_kb_item( name: "ibm/bigfix_remote_control/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:bigfix_remote_control:" );
	if(!cpe){
		cpe = "cpe:/a:ibm:bigfix_remote_control";
	}
	register_product( cpe: cpe, location: "/trc", port: port, service: "www" );
	log_message( data: build_detection_report( app: "IBM BigFix Remote Control", version: version, install: "/trc", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

