if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105173" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-01-20 16:26:22 +0100 (Tue, 20 Jan 2015)" );
	script_name( "Cloudera Manager Detection" );
	script_tag( name: "summary", value: "The script sends a connection
request to the server and attempts to extract the version number
from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7180 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 7180 );
url = "/cmf/login";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "CLOUDERA_MANAGER_SESSIONID" ) || !ContainsString( buf, "<title>Cloudera Manager" )){
	exit( 0 );
}
set_kb_item( name: "cloudera_manager/installed", value: TRUE );
vers = "unknown";
version = eregmatch( pattern: "version: '([^']+)',", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
}
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:cloudera:cloudera_manager:" );
if(isnull( cpe )){
	cpe = "cpe:/a:cloudera:cloudera_manager";
}
register_product( cpe: cpe, location: url, port: port, service: "www" );
log_message( data: build_detection_report( app: "Cloudera Manager", version: vers, install: url, cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

