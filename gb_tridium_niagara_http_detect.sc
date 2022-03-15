if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141355" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-07 16:23:44 +0700 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tridium Niagara Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Tridium Niagara." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/prelogin" );
if(IsMatchRegexp( res, "erver: Niagara Web Server/" ) || ( ContainsString( res, "login/loginN4.js" ) && ContainsString( res, "login/keys.png" ) )){
	version = "unknown";
	set_kb_item( name: "tridium/niagara/detected", value: TRUE );
	set_kb_item( name: "tridium/niagara/http/port", value: port );
	vers = eregmatch( pattern: ".erver: Niagara Web Server/([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "tridium/niagara/http/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "tridium/niagara/http/" + port + "/version", value: version );
}
exit( 0 );

