if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808648" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-09 18:35:29 +0530 (Tue, 09 Aug 2016)" );
	script_name( "Apache Ambari Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Apache Ambari.

  This script sends an HTTP GET request and tries to get the version of Apache
  Ambari from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/javascripts/app.js";
req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate" ) );
rcvRes = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( rcvRes, "HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Ambari" ) && IsMatchRegexp( rcvRes, "Licensed under the Apache License" )){
	version = "unknown";
	install = "/";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	vers = eregmatch( pattern: "App.version = '([0-9]\\.[0-9]\\.[0-9])(\\.[0-9.])?';", string: rcvRes );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "Apache/Ambari/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:apache:ambari:" );
	if(!cpe){
		cpe = "cpe:/a:apache:ambari";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache Ambari", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
}
exit( 0 );

