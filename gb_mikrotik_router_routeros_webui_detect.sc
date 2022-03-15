if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113071" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-14 13:25:48 +0100 (Thu, 14 Dec 2017)" );
	script_name( "MikroTik RouterOS Detection (Web UI)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 10000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of MikroTik RouterOS via Web UI.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 10000 );
res = http_get_cache( port: port, item: "/" );
if(( ContainsString( res, ">RouterOS router configuration page<" ) && ContainsString( res, "mikrotik<" ) && ContainsString( res, ">Login<" ) ) || ( ContainsString( res, ">mikrotik routeros" ) && ContainsString( res, "configuration page</div>" ) )){
	version = "unknown";
	install = port + "/tcp";
	set_kb_item( name: "mikrotik/detected", value: TRUE );
	set_kb_item( name: "mikrotik/www/detected", value: TRUE );
	vers = eregmatch( pattern: ">RouterOS v([A-Za-z0-9.]+)<", string: res );
	if(!vers[1]){
		vers = eregmatch( pattern: ">mikrotik routeros ([A-Za-z0-9.]+) configuration page<", string: res );
	}
	if(vers[1]){
		version = vers[1];
	}
	if(version != "unknown"){
		set_kb_item( name: "mikrotik/webui/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "mikrotik/webui/port", value: port );
	set_kb_item( name: "mikrotik/webui/" + port + "/version", value: version );
}
exit( 0 );

