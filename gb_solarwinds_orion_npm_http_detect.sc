if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100940" );
	script_version( "2021-05-26T09:57:42+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 09:57:42 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SolarWinds Orion Network Performance Monitor (NPM) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8787 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the SolarWinds Orion Network Performance
  Monitor (NPM)." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8787 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
dir = "/Orion";
url = NASLString( dir, "/Login.aspx" );
buf = http_get_cache( item: url, port: port );
if(!buf){
	exit( 0 );
}
if(( ContainsString( buf, "SolarWinds Platform" ) || ContainsString( buf, "SolarWinds Orion" ) || ContainsString( buf, "Orion Platform" ) ) && IsMatchRegexp( buf, "(NPM|Network Performance Monitor)" )){
	version = "unknown";
	vers = eregmatch( string: buf, pattern: "(NPM|Network Performance Monitor) v?(([0-9.]+).?([A-Z0-9]+))", icase: TRUE );
	if( !isnull( vers[2] ) ){
		set_kb_item( name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[2] );
		set_kb_item( name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0] );
	}
	else {
		vers = eregmatch( string: buf, pattern: "NPM[^:]+: ([0-9.]+)" );
		if(!isnull( vers[1] )){
			set_kb_item( name: "solarwinds/orion/npm/http/" + port + "/version", value: vers[1] );
			set_kb_item( name: "solarwinds/orion/npm/http/" + port + "/concluded", value: vers[0] );
		}
	}
	set_kb_item( name: "solarwinds/orion/npm/detected", value: TRUE );
	set_kb_item( name: "solarwinds/orion/npm/http/port", value: port );
	set_kb_item( name: "solarwinds/orion/npm/http/" + port + "/location", value: dir );
}
exit( 0 );

