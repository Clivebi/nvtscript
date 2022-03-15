if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809483" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-02 19:00:32 +0530 (Fri, 02 Dec 2016)" );
	script_name( "Apache Ranger Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Apache Ranger.

  This script sends an HTTP GET request and tries to get the version of
  Apache Ranger from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 6080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 6080 );
res = http_get_cache( item: "/login.jsp", port: port );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Ranger - Sign In</title>" ) && ContainsString( res, "Username:<" ) && ContainsString( res, "Password:<" )){
	version = "unknown";
	install = "/";
	set_kb_item( name: "Apache/Ranger/Installed", value: TRUE );
	cpe = "cpe:/a:apache:ranger";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache Ranger", version: version, install: install, cpe: cpe, concluded: version ), port: port );
}
exit( 0 );

