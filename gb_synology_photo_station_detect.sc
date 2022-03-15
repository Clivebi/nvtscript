if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105279" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-05-26 13:47:01 +0200 (Tue, 26 May 2015)" );
	script_name( "Synology Photo Station Detection" );
	script_tag( name: "summary", value: "The script sends a connection
request to the server and attempts to extract the version number
from the reply." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/photo/";
buf = http_get_cache( item: url, port: port );
if(( !IsMatchRegexp( buf, "<title>(Synology )?Photo Station [0-9]{1}</title>" ) && !IsMatchRegexp( buf, "content=\"Synology Photo Station [0-9]{1}" ) ) || !ContainsString( buf, "webapi/auth.php" )){
	exit( 0 );
}
cpe = "cpe:/a:synology:synology_photo_station";
set_kb_item( name: "synology_photo_station/installed", value: TRUE );
psv = "unknown";
ps_version = eregmatch( pattern: "<title>Photo Station ([0-9]{1})</title>", string: buf );
if( !isnull( ps_version[1] ) ){
	psv = ps_version[1];
	set_kb_item( name: "synology_photo_station/psv", value: psv );
}
else {
	ps_version = eregmatch( pattern: "content=\"Synology Photo Station ([0-9]{1})", string: buf );
	if(!isnull( ps_version[1] )){
		psv = ps_version[1];
		set_kb_item( name: "synology_photo_station/psv", value: psv );
	}
}
vers = "unknown";
version = eregmatch( pattern: "\\.js\\?v=([0-9.-]+)", string: buf );
if(!isnull( version[1] )){
	if( egrep( pattern: "\\.", string: version[1] ) ){
		vers = version[1];
		cpe += ":" + vers;
		set_kb_item( name: "synology_photo_station/version", value: vers );
	}
	else {
		version[0] = "";
	}
}
register_product( cpe: cpe, location: url, port: port, service: "www" );
log_message( data: build_detection_report( app: "Synology Photo Station " + psv, version: vers, install: url, cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

