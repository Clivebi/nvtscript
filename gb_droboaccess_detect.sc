if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142073" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-06 09:53:10 +0700 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drobo DroboAccess Detection" );
	script_tag( name: "summary", value: "Detection of Drobo DroboAccess.

The script sends a connection request to the server and attempts to detect Drobo DroboAccess, a web interface
for Drobo NAS devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8060, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8060 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/index.php/login" );
if(ContainsString( res, "Drobo Access" ) && ContainsString( res, "class=\"infield\">Password" )){
	set_kb_item( name: "drobo/nas/detected", value: TRUE );
	set_kb_item( name: "drobo/droboaccess/detected", value: TRUE );
	set_kb_item( name: "drobo/droboaccess/port", value: port );
}
res = http_get_cache( port: port, item: "/DroboAccess/" );
if(ContainsString( res, "title>DroboAccess DroboApp</title>" ) && ContainsString( res, "Password strength" )){
	set_kb_item( name: "drobo/nas/detected", value: TRUE );
	set_kb_item( name: "drobo/droboaccess/detected", value: TRUE );
	set_kb_item( name: "drobo/droboaccess/port", value: port );
}
exit( 0 );

