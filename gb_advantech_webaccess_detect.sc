if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804429" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-04-16 14:24:35 +0530 (Wed, 16 Apr 2014)" );
	script_name( "Advantech WebAccess Version Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Advantech WebAccess.

The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
res = http_get_cache( item: "/broadWeb/bwRoot.asp", port: port );
if(!res || !ContainsString( res, "Advantech WebAccess" )){
	exit( 0 );
}
set_kb_item( name: "advantech/webaccess/detected", value: TRUE );
set_kb_item( name: "advantech/webaccess/http/" + port + "/detected", value: TRUE );
version = "unknown";
concluded = "HTTP Request";
vers = eregmatch( pattern: "Software Build : ([0-9.-]+)", string: res );
if(!vers[1]){
	vers = eregmatch( pattern: "class=e5>.*: ([0-9.-]+)", string: res );
}
if( !isnull( vers[1] ) ){
	version = str_replace( string: vers[1], find: "-", replace: "." );
}
else {
	vers = eregmatch( pattern: "class=\"version\">.*: ([0-9.-]+)", string: res );
	if(!isnull( vers[1] )){
		version = str_replace( string: vers[1], find: "-", replace: "." );
	}
}
set_kb_item( name: "advantech/webaccess/http/" + port + "/version", value: version );
set_kb_item( name: "advantech/webaccess/http/" + port + "/concluded", value: vers[0] );
set_kb_item( name: "advantech/webaccess/http/" + port + "/location", value: "/broadWeb/" );
set_kb_item( name: "advantech/webaccess/http/port", value: port );
exit( 0 );

