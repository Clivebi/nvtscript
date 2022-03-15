if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112451" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-06 10:55:11 +0100 (Thu, 06 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cradlepoint Routers Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Cradlepoint routers." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
buf = http_get_cache( item: "/login/", port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "manufacturer: \"Cradlepoint Inc.\"" ) || ( ContainsString( buf, "cplogin = window.cplogin" ) && ContainsString( buf, "cplogin.state" ) ) )){
	model = "unknown";
	fw_version = "unknown";
	mod = eregmatch( pattern: "cplogin.model = \"([A-Za-z0-9-]+)\";", string: buf, icase: TRUE );
	if(mod[1]){
		model = mod[1];
		set_kb_item( name: "cradlepoint/router/http/" + port + "/concluded", value: mod[0] );
	}
	fw = eregmatch( pattern: "cplogin.version = \"([0-9.]+) ", string: buf );
	if(fw[1]){
		fw_version = fw[1];
	}
	set_kb_item( name: "cradlepoint/router/http/" + port + "/model", value: model );
	set_kb_item( name: "cradlepoint/router/http/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "cradlepoint/router/http/detected", value: TRUE );
	set_kb_item( name: "cradlepoint/router/http/port", value: port );
	set_kb_item( name: "cradlepoint/router/detected", value: TRUE );
}
exit( 0 );

