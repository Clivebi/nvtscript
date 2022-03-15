if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141570" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-05 11:56:43 +0700 (Fri, 05 Oct 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "D-Link Central WiFiManager Software Controller Detection (HTTP" );
	script_tag( name: "summary", value: "Detection of D-Link Central WiFiManager Software Controller.

The script sends a HTTP connection request to the server and attempts to detect D-Link Central WiFiManager
Software Controller." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/Lang/en-US/common.js" );
if(ContainsString( res, "Central WiFiManager" )){
	set_kb_item( name: "dlink_central_wifimanager/detected", value: TRUE );
	set_kb_item( name: "dlink_central_wifimanager/http/port", value: port );
	exit( 0 );
}
exit( 0 );

