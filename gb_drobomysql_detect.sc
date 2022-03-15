if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142076" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-06 09:53:46 +0700 (Wed, 06 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drobo MySQL Web Interface Detection" );
	script_tag( name: "summary", value: "Detection of Drobo MySQL Web Interface.

The script sends a connection request to the server and attempts to detect Drobo MySQL Web Interface." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/mysql/" );
if(ContainsString( res, "appname\">DroboApp" ) && ContainsString( res, "/DroboAppsService.js" ) && ContainsString( res, "></span> Start" )){
	set_kb_item( name: "drobo/nas/detected", value: TRUE );
	set_kb_item( name: "drobo/mysqlapp/detected", value: TRUE );
	set_kb_item( name: "drobo/mysqlapp/port", value: port );
	url = "/mysql/api/drobo.php";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	model = eregmatch( pattern: "\"mModel\":\"([^\"]+)", string: res );
	if(!isnull( model[1] )){
		set_kb_item( name: "drobo/mysqlapp/model", value: model[1] );
	}
	version = eregmatch( pattern: "\"mVersion\":\"([^\"]+)", string: res );
	if(!isnull( version[1] )){
		version = str_replace( string: version[1], find: " ", replace: "" );
		version = str_replace( string: version, find: "[", replace: "." );
		version = str_replace( string: version, find: "]", replace: "" );
		version = str_replace( string: version, find: "-", replace: "." );
		set_kb_item( name: "drobo/mysqlapp/fw_version", value: version );
	}
	esaid = eregmatch( pattern: "\"mESAID\":\"([^\"]+)", string: res );
	if(!isnull( esaid[1] )){
		set_kb_item( name: "drobo/mysqlapp/esaid", value: esaid[1] );
	}
}
exit( 0 );

