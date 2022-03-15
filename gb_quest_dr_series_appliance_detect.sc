if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813011" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-12 13:08:38 +0530 (Mon, 12 Mar 2018)" );
	script_name( "Quest DR Series Appliance Remote Detection" );
	script_tag( name: "summary", value: "Detection of Quest DR Series Appliance.

  The script sends a connection request to the server and attempts to detect the
  presence of Quest DR Series Appliance." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "ng-app=\"drConsoleApp" ) && ContainsString( res, "<dr-masthead-application-name>" )){
	version = "unknown";
	data = "{\"jsonrpc\":\"2.0\",\"method\":\"getPreLoginInfo\",\"params\":{\"classname\":\"DRPreLoginAccess\"},\"id\":1}";
	url = "/ws/v1.0/jsonrpc";
	headers = make_array( "Content-Type", "application/json-rpc" );
	req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers = eregmatch( pattern: "\"version\":\"([0-9a-z.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	mod = eregmatch( pattern: "\"product_name\":\"([^ ]+ )?([^\"]+)", string: res );
	if(!isnull( mod[2] )){
		model = mod[2];
	}
	set_kb_item( name: "quest/dr/appliance/detected", value: TRUE );
	if( model ){
		cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:quest:" + tolower( model ) + ":" );
		if(!cpe){
			cpe = "cpe:/a:quest:" + tolower( model );
		}
	}
	else {
		cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:quest:disk_backup:" );
		if(!cpe){
			cpe = "cpe:/a:quest:disk_backup";
		}
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Quest DR Series " + model, version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

