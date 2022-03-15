if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809732" );
	script_version( "2020-12-16T09:35:48+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-16 09:35:48 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2016-11-25 16:04:15 +0530 (Fri, 25 Nov 2016)" );
	script_name( "Oracle BI Publisher Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9704 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Oracle BI Publisher." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9704 );
res = http_get_cache( item: "/xmlpserver/login.jsp", port: port );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
if(( ContainsString( res, "<title>Oracle BI Publisher" ) && ContainsString( res, "Login</title>" ) ) || ContainsString( res, "class=\"Copyright\">Oracle BI Publisher" ) || ContainsString( res, "name=\"Generator\" content=\"Oracle BI Publisher" )){
	version = "unknown";
	extra = "";
	vers = eregmatch( pattern: "content=\"Oracle BI Publisher ([0-9.]+)( .build# ([0-9.]+))?", string: res );
	if(vers[1]){
		version = vers[1];
	}
	if(vers[3]){
		extra += "Build: " + vers[3];
	}
	if(version == "unknown"){
		vers = eregmatch( pattern: "\"Copyright\">Oracle BI Publisher ([0-9.]+)", string: res, icase: TRUE );
		if(vers[1]){
			version = vers[1];
		}
	}
	set_kb_item( name: "oracle/bi_publisher/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:oracle:business_intelligence_publisher:" );
	if(!cpe){
		cpe = "cpe:/a:oracle:business_intelligence_publisher";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Oracle BI Publisher", version: version, install: "/", cpe: cpe, extra: extra, concluded: vers[0] ), port: port );
}
exit( 0 );

