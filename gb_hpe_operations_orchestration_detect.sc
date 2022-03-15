if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813101" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-26 17:54:51 +0530 (Mon, 26 Mar 2018)" );
	script_name( "HPE Operations Orchestration Remote Detection" );
	script_tag( name: "summary", value: "Detection of running version of HPE Operations
  Orchestration.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
hpePort = http_get_port( default: 8080 );
res = http_get_cache( port: hpePort, item: "/oo/" );
if(( ContainsString( res, ">HPE Operations Orchestration<" ) && ContainsString( res, "Server: OO" ) ) || ( ContainsString( res, "Server: OO" ) && IsMatchRegexp( res, "Location.*oo/login/login-form" ) && ContainsString( res, "302 Found" ) )){
	set_kb_item( name: "hpe/operations/orchestration/installed", value: TRUE );
	req = http_get( item: "/oo/rest/latest/version", port: hpePort );
	res = http_keepalive_send_recv( port: hpePort, data: req );
	if( IsMatchRegexp( res, "HTTP/1.. 200 OK" ) && ContainsString( res, "\"version\"" ) && ContainsString( res, "\"revision\"" ) && ContainsString( res, "\"build" ) ){
		version = eregmatch( pattern: "\"version\":\"([0-9.]+)", string: res );
		if(version[1]){
			hpeVer = version[1];
		}
	}
	else {
		url1 = "/online-help/Content";
		for url2 in make_list( "/_HPc_HomePage_HPE_SW.htm",
			 "/HelpCenter_Home.htm" ) {
			url = url1 + url2;
			req = http_get( item: url, port: hpePort );
			res = http_keepalive_send_recv( port: hpePort, data: req );
			if(IsMatchRegexp( res, "HTTP/1.. 200 OK" ) && ContainsString( res, "productName=\"Operations Orchestration" ) && ContainsString( res, "Help Center" ) && IsMatchRegexp( res, "topicTitle.*Operations Orchestration" )){
				version = eregmatch( pattern: "productVersion=\"([0-9.]+)\"", string: res );
				if(version[1]){
					hpeVer = version[1];
					break;
				}
			}
		}
	}
	if(hpeVer){
		set_kb_item( name: NASLString( "www/", hpePort, "/oo" ), value: hpeVer );
		cpe = build_cpe( value: hpeVer, exp: "^([0-9.]+)", base: "cpe:/a:hp:operations_orchestration:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:hp:operations_orchestration";
		}
		register_product( cpe: cpe, location: hpePort + "/tcp", port: hpePort, service: "www" );
		log_message( data: build_detection_report( app: "HPE Operations Orchestration", version: hpeVer, install: hpePort + "/tcp", cpe: cpe, concluded: hpeVer ), port: hpePort );
		exit( 0 );
	}
}
exit( 0 );

