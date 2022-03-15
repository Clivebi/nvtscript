if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800988" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Zenoss Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Zenoss Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
req = http_get( item: "/zport/acl_users/cookieAuthHelper/login_form", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "Zenoss Login" )){
	exit( 0 );
}
install = "/";
version = "unknown";
vers = eregmatch( pattern: "<span>([0-9.]+)", string: res );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "www/" + port + "/Zenoss", value: version );
set_kb_item( name: "ZenossServer/detected", value: TRUE );
register_and_report_cpe( app: "Zenoss Server", ver: version, concluded: vers[0], base: "cpe:/a:zenoss:zenoss:", expr: "^([0-9.]+)", insloc: install, regPort: port );
exit( 0 );

