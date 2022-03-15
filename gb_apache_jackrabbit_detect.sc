if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807896" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-06 14:29:25 +0530 (Thu, 06 Oct 2016)" );
	script_name( "Apache Jackrabbit Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Apache Jackrabbit.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
jackPort = http_get_port( default: 80 );
res = http_get_cache( port: jackPort, item: "/" );
if(ContainsString( res, ">Jackrabbit JCR Server" ) && ContainsString( res, "jackrabbit.apache.org" )){
	url = "/repository/default/";
	req = http_get( port: jackPort, item: url );
	res = http_keepalive_send_recv( port: jackPort, data: req );
	vers = eregmatch( pattern: ">Jackrabbit<.*version ([0-9.]+)<", string: res );
	if( vers[1] ){
		version = vers[1];
	}
	else {
		version = "unknown";
	}
	set_kb_item( name: "apache/jackrabbit/installed", value: TRUE );
	if(version != "unknown"){
		set_kb_item( name: "apache/jackrabbit/version", value: version );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:jackrabbit:" );
	if(!cpe){
		cpe = "cpe:/a:apache:jackrabbit";
	}
	register_product( cpe: cpe, location: "/", port: jackPort, service: "www" );
	log_message( data: build_detection_report( app: "Apache Jackrabbit", version: version, install: "/", cpe: cpe, concluded: version ), port: jackPort );
	exit( 0 );
}
exit( 0 );

