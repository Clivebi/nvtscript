if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111080" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-02-01 11:00:00 +0100 (Mon, 01 Feb 2016)" );
	script_name( "Tinyproxy Detection (HTTP)" );
	script_tag( name: "summary", value: "Detects the installed version of Tinyproxy.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "proxy_use.sc", "global_settings.sc" );
	script_require_ports( "Services/http_proxy", 3128, 8888, "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://tinyproxy.github.io/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
ports = make_list();
proxy_ports = service_get_ports( default_port_list: make_list( 3128,
	 8888 ), proto: "http_proxy" );
if(proxy_ports){
	ports = make_list( ports,
		 proxy_ports );
}
www_ports = http_get_ports( default_port_list: make_list( 8080 ) );
if(www_ports){
	ports = make_list( ports,
		 www_ports );
}
for port in ports {
	req = http_get( item: "http://www.$$$$$", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(data = egrep( pattern: "^Server\\s*:\\s*tinyproxy", string: res, icase: TRUE )){
		version = "unknown";
		install = port + "/tcp";
		ver = eregmatch( pattern: "^Server\\s*:\\s*tinyproxy/([0-9.]+)", string: data, icase: TRUE );
		if(ver[1]){
			version = ver[1];
		}
		set_kb_item( name: "tinyproxy/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:banu:tinyproxy:" );
		if(!cpe){
			cpe = "cpe:/a:banu:tinyproxy";
		}
		register_product( cpe: cpe, location: install, port: port, service: "http_proxy" );
		log_message( data: build_detection_report( app: "Tinyproxy", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

