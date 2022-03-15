if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112030" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-08-31 13:26:04 +0200 (Thu, 31 Aug 2017)" );
	script_name( "Apache Atlas Version Detection" );
	script_tag( name: "summary", value: "Detection of installed version
  of Apache Atlas.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 21000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 21000 );
rcvRes = http_get_cache( port: port, item: "/#!/search" );
if(IsMatchRegexp( rcvRes, "HTTP/1.. 200" ) && ContainsString( rcvRes, "<title>Apache Atlas</title>" ) && ContainsString( rcvRes, "/modules/home/views/header.html" )){
	version = "unknown";
	set_kb_item( name: "Apache/Atlas/Installed", value: TRUE );
	req = http_get( port: port, item: "/api/atlas/admin/version" );
	res = http_keepalive_send_recv( port: port, data: req );
	ver = eregmatch( pattern: "\"Version\":\"([0-9.]+)[^\"]+", string: res );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "Apache/Atlas/version", value: version );
		url = "/api/atlas/admin/version";
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:atlas:" );
	if(!cpe){
		cpe = "cpe:/a:apache:atlas";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache Atlas", version: version, install: "/", cpe: cpe, concluded: ver[0], concludedUrl: url ), port: port );
}
exit( 0 );

