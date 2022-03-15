if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107004" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "creation_date", value: "2016-05-20 10:42:39 +0100 (Fri, 20 May 2016)" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Meteocontrol WEB'log Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the server and
  attempts to identify a Meteocontrol WEB'log Application existence from the reply ." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/html/en/index.html";
buf = http_get_cache( item: url, port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "WEB'log" ) && ContainsString( buf, "System Survey of the Plant" ) && ContainsString( buf, "<div class=\"cProductname\">&nbsp;WEB&#180;log</div>" )){
	set_kb_item( name: "meteocontrol/weblog/installed", value: TRUE );
	install = "/";
	version = "unknown";
	cpe = "cpe:/a:meteocontrol:weblog";
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Meteocontrol WEBlog", version: version, install: install, cpe: cpe, concludedUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) ), port: port );
}
exit( 0 );

