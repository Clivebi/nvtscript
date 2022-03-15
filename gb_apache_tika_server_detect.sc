if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810251" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)" );
	script_name( "Apache Tika Server Version Detection" );
	script_tag( name: "summary", value: "This script sends an HTTP GET request to figure out
  whether Apache Tika Server is running on the target host, and, if so, which version is installed." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9998 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9998 );
url1 = "/";
res1 = http_get_cache( item: url1, port: port );
url2 = "/version";
res2 = http_get_cache( item: url2, port: port );
if(( res1 && ( IsMatchRegexp( res1, "<title>Welcome to the Apache Tika.*Server</title>" ) || ( IsMatchRegexp( res1, "Apache Tika.*" ) && ContainsString( res1, "For endpoints, please see" ) ) ) ) || res2 && IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && egrep( string: res2, pattern: "^Apache Tika ([0-9.]+)", icase: FALSE )){
	version = "unknown";
	ver = eregmatch( pattern: "<title>Welcome to the Apache Tika ([0-9.]+) Server</title>", string: res1 );
	if(ver[1]){
		version = ver[1];
		conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
	}
	if(version == "unknown"){
		if(ver = egrep( pattern: "^Apache Tika ([0-9.]+)", string: res1, icase: FALSE )){
			ver = eregmatch( pattern: "Apache Tika ([0-9.]+)", string: ver );
			if(ver[1]){
				version = ver[1];
				conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			}
		}
	}
	if(version == "unknown"){
		req = http_get( item: url2, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		ver = eregmatch( pattern: "^Apache Tika ([0-9.]+)", string: res );
		if(ver[1]){
			version = ver[1];
			conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
		}
	}
	set_kb_item( name: "Apache/Tika/Server/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:tika:" );
	if(!cpe){
		cpe = "cpe:/a:apache:tika";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache Tika Server", version: version, install: "/", cpe: cpe, concluded: ver[0], concludedUrl: conclUrl ), port: port );
}
exit( 0 );

