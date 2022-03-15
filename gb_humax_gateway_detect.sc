if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106916" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-07-03 11:22:04 +0700 (Mon, 03 Jul 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HUMAX Gateway Detection" );
	script_tag( name: "summary", value: "Detection of HUMAX Gateway devices.

  The script sends a connection request to the server and attempts to detect HUMAX Gateway devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://americas.humaxdigital.com/gateway/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "HUMAX" ) && ContainsString( res, "<title id=\"model_title\">Quick Setup</title>" ) && ContainsString( res, "<legend>Login Area</legend>" )){
	version = "unknown";
	url = "/api";
	data = "{\"method\":\"Device.getDBInfo\",\"id\":90,\"jsonrpc\":\"2.0\",\"params\":{\"IMG_CurrentModel\":\"\",\"Device_vendor\":\"\"}}";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With", "XMLHttpRequest" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	mod = eregmatch( pattern: "IMG_CurrentModel\" : \"([^\"]+)", string: res );
	if( !isnull( mod[1] ) ){
		model = mod[1];
		set_kb_item( name: "humax_gateway/model", value: model );
	}
	else {
		exit( 0 );
	}
	set_kb_item( name: "humax_gateway/detected", value: TRUE );
	cpe = "cpe:/a:humaxdigital:" + tolower( model );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "HUMAX " + model, version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

