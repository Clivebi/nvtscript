if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141285" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-10 08:56:51 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine Exchange Reporter Plus Detection" );
	script_tag( name: "summary", value: "Detection of ManageEngine Exchange Reporter Plus.

The script sends a connection request to the server and attempts to detect ManageEngine Exchange Reporter Plus and
to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8181 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/exchange-reports/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8181 );
res = http_get_cache( port: port, item: "/exchange/Home.do" );
if(ContainsString( res, "<title>ManageEngine - Exchange Reporter Plus</title>" ) && ContainsString( res, "Exchange services" )){
	version = "version";
	vers = eregmatch( pattern: "\\.js\\?v=([0-9]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "me_exchange_reporter/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9]+)", base: "cpe:/a:zohocorp:manageengine_exchange_reporter_plus:" );
	if(!cpe){
		cpe = "cpe:/a:zohocorp:manageengine_exchange_reporter_plus";
	}
	register_product( cpe: cpe, location: "/exchange", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ManageEngine Exchange Reporter Plus", version: version, install: "/exchange", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

