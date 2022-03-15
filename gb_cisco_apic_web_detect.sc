if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105534" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-02-10 12:03:48 +0100 (Wed, 10 Feb 2016)" );
	script_name( "Cisco Application Policy Infrastructure Controller Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( port: port, item: "/" );
if(!ContainsString( buf, "<title>APIC</title>" )){
	exit( 0 );
}
url = "/insieme/stromboli/meta/Version.js";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "insieme.stromboli.meta.Version" ) || !ContainsString( buf, "versionString:" )){
	exit( 0 );
}
set_kb_item( name: "cisco/application_policy_infrastructure_controller/installed", value: TRUE );
cpe = "cpe:/a:cisco:application_policy_infrastructure_controller";
version = eregmatch( pattern: "versionString: '([^']+)'", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "cisco/application_policy_infrastructure_controller/version", value: vers );
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Cisco Application Policy Infrastructure Controller", version: vers, install: "/", cpe: cpe, concluded: version[0], concludedUrl: url ), port: port );
exit( 0 );

