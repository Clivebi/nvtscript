if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108341" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-16 10:43:37 +0100 (Fri, 16 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PRUFTECHNIK VIBNODE Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the remote host and attempts
  to detect the presence of a PRUFTECHNIK VIBNODE device." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(IsMatchRegexp( banner, "^HTTP/1\\.[01] 401" ) && ContainsString( banner, "WWW-Authenticate: Basic realm=\"VibNode\"" )){
	app_version = "unknown";
	os_version = "unknown";
	set_kb_item( name: "vibnode/detected", value: TRUE );
	set_kb_item( name: "vibnode/http/detected", value: TRUE );
	set_kb_item( name: "vibnode/http/port", value: port );
	set_kb_item( name: "vibnode/http/" + port + "/concluded", value: banner );
	set_kb_item( name: "vibnode/http/" + port + "/app_version", value: app_version );
	set_kb_item( name: "vibnode/http/" + port + "/os_version", value: os_version );
}
exit( 0 );

