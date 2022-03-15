if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902258" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)" );
	script_name( "SmarterMail Version Detection" );
	script_tag( name: "summary", value: "Detection of SmarterMail version.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 9998 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
smPort = http_get_port( default: 9998 );
if(!http_can_host_asp( port: smPort )){
	exit( 0 );
}
SmRes = http_get_cache( item: "/Login.aspx", port: smPort );
if(!ContainsString( SmRes, ">SmarterMail" ) && !ContainsString( SmRes, ">SmarterMail Enterprise" ) && !ContainsString( SmRes, ">SmarterMail Standard" )){
	exit( 0 );
}
version = "unknown";
ver = eregmatch( pattern: ">SmarterMail [a-zA-Z]+ ([0-9.]+)<", string: SmRes );
if(ver[1]){
	version = ver[1];
}
set_kb_item( name: "SmarterMail/Ver", value: version );
set_kb_item( name: "SmarterMail/installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:smartertools:smartermail:" );
if(!cpe){
	cpe = "cpe:/a:smartertools:smartermail";
}
register_product( cpe: cpe, location: "/", port: smPort, service: "www" );
log_message( data: build_detection_report( app: "SmarterMail", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: smPort );
exit( 0 );

