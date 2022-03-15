if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107247" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-16 16:22:38 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Rancher Detection" );
	script_tag( name: "summary", value: "Detection of Rancher Server.

The script sends a connection request to the server and attempts to detect Rancher and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://rancher.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/login/";
res = http_get_cache( port: port, item: url );
if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "PL=rancher" ) && ContainsString( res, "X-Rancher-Version" ) ){
	detected = TRUE;
}
else {
	res2 = http_get_cache( port: port, item: "/" );
	file = eregmatch( pattern: "<script src=\"(\\/?assets\\/ui(-[^\\.]+)?\\.js)\"", string: res2, icase: TRUE );
	if(!isnull( file[1] )){
		filename = file[1];
		if(filename[0] != "/"){
			url2 = "/";
		}
		url2 = url2 + filename;
		res3 = http_get_cache( port: port, item: url2 );
		if(ContainsString( res3, "Rancher" )){
			detected = TRUE;
		}
	}
}
if(detected){
	version = "unknown";
	ver = eregmatch( pattern: "X-Rancher-Version: v([0-9.]+)", string: res );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "rancher/version", value: version );
	}
	set_kb_item( name: "rancher/detected", value: TRUE );
	res = http_get_cache( port: port, item: "/v1" );
	if( IsMatchRegexp( res, "apiEndpoint:\\s*\"/v1\"" ) || ContainsString( res, "\"id\":\"v1\"" ) || ContainsString( res, "\"type\":\"error\"" ) ){
		hostType = "v1";
	}
	else {
		res = http_get_cache( port: port, item: "/v3" );
		if(ContainsString( res, "\"message\":\"must authenticate\"" )){
			hostType = "v3";
		}
	}
	if(!isnull( hostType )){
		set_kb_item( name: "rancher/type", value: hostType );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:rancher:rancher:" );
	if(!cpe){
		cpe = "cpe:/a:rancher:rancher";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Rancher", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: port );
	exit( 0 );
}
exit( 0 );

