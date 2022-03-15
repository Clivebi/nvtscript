if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106151" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-07-25 13:42:49 +0700 (Mon, 25 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Barracuda Load Balancer Detection" );
	script_tag( name: "summary", value: "Detection of Barracuda Load Balancer.

  The script sends a connection request to the server and attempts to detect the presence of Barracuda Load
  Balancer and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.barracuda.com/products/loadbalancer" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
url = "/cgi-mod/index.cgi";
res = http_get_cache( port: port, item: url );
if(egrep( pattern: "<title>Barracuda Load Balancer", string: res, icase: TRUE ) || ( ContainsString( res, "<span>Barracuda</span>" ) && ContainsString( res, "a=blb_product" ) )){
	version = "unknown";
	vers = eregmatch( string: res, pattern: "barracuda\\.css\\?v=([0-9.]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "barracuda/loadbalancer/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:barracuda:load_balancer_adc_firmware:" );
	if(!cpe){
		cpe = "cpe:/o:barracuda:load_balancer_adc_firmware";
	}
	os_register_and_report( os: "Barracuda Load Balancer Firmware", cpe: cpe, desc: "Barracuda Load Balancer Detection", runs_key: "unixoide" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Barracuda Load Balancer", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

