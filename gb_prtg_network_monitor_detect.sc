if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103048" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-27 12:55:42 +0100 (Thu, 27 Jan 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PRTG Network Monitor Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "PRTG/banner" );
	script_xref( name: "URL", value: "http://www.paessler.com/prtg" );
	script_tag( name: "summary", value: "Detection of PRTG Network Monitor.

  The script attempts to identify PRTG Network Monitor and to extract the version number." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: PRTG/" )){
	exit( 0 );
}
url = "/index.htm";
buf = http_get_cache( item: url, port: port );
if(egrep( pattern: "PRTG Network Monitor", string: buf, icase: TRUE )){
	install = "/";
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "Server: PRTG/([0-9.]+)", icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "www/" + port + "/prtg_network_monitor", value: vers + " under " + install );
	set_kb_item( name: "prtg_network_monitor/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:paessler:prtg_network_monitor:" );
	if(!cpe){
		cpe = "cpe:/a:paessler:prtg_network_monitor";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "PRTG Network Monitor", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
	exit( 0 );
}
exit( 0 );

