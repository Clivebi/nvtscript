if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142110" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-08 15:17:54 +0700 (Fri, 08 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drobo DroboPix Detection" );
	script_tag( name: "summary", value: "Detection of Drobo DroboPix.

The script sends a connection request to the server and attempts to detect Drobo DroboPix, s a one-click photo
upload solution for mobile devices on Drobo NAS devices." );
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
res = http_get_cache( port: port, item: "/DroboPix/" );
if(ContainsString( res, ">DroboApp</title>" ) && ContainsString( res, "webui.drobopix" )){
	set_kb_item( name: "drobo/nas/detected", value: TRUE );
	set_kb_item( name: "drobo/drobopix/detected", value: TRUE );
	set_kb_item( name: "drobo/drobopix/port", value: port );
	url = "/DroboPix/api/drobo.php";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	model = eregmatch( pattern: "\"mModel\":\"([^\"]+)", string: res );
	if(!isnull( model[1] )){
		set_kb_item( name: "drobo/drobopix/model", value: model[1] );
	}
	version = eregmatch( pattern: "\"mVersion\":\"([^\"]+)", string: res );
	if(!isnull( version[1] )){
		version = str_replace( string: version[1], find: " ", replace: "" );
		version = str_replace( string: version, find: "[", replace: "." );
		version = str_replace( string: version, find: "]", replace: "" );
		version = str_replace( string: version, find: "-", replace: "." );
		set_kb_item( name: "drobo/drobopix/fw_version", value: version );
	}
	esaid = eregmatch( pattern: "\"mESAID\":\"([^\"]+)", string: res );
	if(!isnull( esaid[1] )){
		set_kb_item( name: "drobo/drobopix/esaid", value: esaid[1] );
	}
}
exit( 0 );

