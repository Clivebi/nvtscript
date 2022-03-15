if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17368" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-05-05T09:44:01+0000" );
	script_tag( name: "last_modification", value: "2020-05-05 09:44:01 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WebShield Appliance detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of WebShield Appliance.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	exit( 0 );
}
require("http_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = 443;
if(!get_port_state( port )){
	exit( 0 );
}
req = http_get( item: "/strings.js", port: port );
res = http_send_recv( data: req, port: port );
if(ContainsString( res, "Server: WebShield Appliance" )){
	title = egrep( pattern: "WEBSHIELD_TITLE=", string: res );
	if(!title){
		exit( 0 );
	}
	vers = "unknown";
	version = eregmatch( pattern: "WEBSHIELD_TITLE=\"WebShield Appliance v(0-9.)+\"", string: title, icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:network_associates:webshield:" );
	if(!cpe){
		cpe = "cpe:/a:network_associates:webshield";
	}
	register_product( cpe: cpe, location: "/strings.js", port: port, service: "www" );
	log_message( data: build_detection_report( app: "WebShield Appliance", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

