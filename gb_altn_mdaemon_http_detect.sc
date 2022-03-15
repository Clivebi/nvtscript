if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113575" );
	script_version( "2021-09-09T10:20:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:20:36 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-22 15:02:03 +0200 (Fri, 22 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Alt-N MDaemon Mail Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Alt-N MDaemon Mail Server." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(( IsMatchRegexp( res, "MDaemon[- ]Webmail" ) || IsMatchRegexp( res, "Server\\s*:\\s*WDaemon" ) ) && ContainsString( res, "WorldClient.dll" )){
	version = "unknown";
	set_kb_item( name: "altn/mdaemon/detected", value: TRUE );
	set_kb_item( name: "altn/mdaemon/http/detected", value: TRUE );
	set_kb_item( name: "altn/mdaemon/http/port", value: port );
	vers = eregmatch( pattern: "\\.js\\?v=([0-9.]+)", string: res );
	if(isnull( vers[1] )){
		vers = eregmatch( pattern: "MDaemon.*v([0-9.]+)", string: res );
	}
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "altn/mdaemon/http/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "altn/mdaemon/http/" + port + "/version", value: version );
}
exit( 0 );

