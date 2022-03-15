if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10757" );
	script_version( "2021-08-09T14:28:51+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 14:28:51 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Webmin / Usermin Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Alert4Web.com" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 10000, 20000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Webmin / Usermin." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
ports = http_get_ports( default_port_list: make_list( 10000,
	 20000 ), ignore_broken: TRUE );
for port in ports {
	banner = http_get_remote_headers( port: port, ignore_broken: TRUE );
	buf = http_get_cache( item: "/", port: port );
	if(!banner && !buf){
		continue;
	}
	found = FALSE;
	concluded = NULL;
	if(banner && concl = egrep( pattern: "(^Server\\s*:\\s*MiniServ|Basic realm=\"Usermin Server\")", string: banner, icase: TRUE )){
		found = TRUE;
		concluded = chomp( concl );
	}
	if(buf && concl = egrep( pattern: ">Login to (Web|User)min<", string: buf, icase: FALSE )){
		found = TRUE;
		if(concluded){
			concluded += "\n";
		}
		concluded += chomp( concl );
	}
	if(found){
		vers = "unknown";
		webmin = FALSE;
		usermin = FALSE;
		set_kb_item( name: "usermin_or_webmin/installed", value: TRUE );
		if( ContainsString( buf, ">Login to Webmin<" ) && !IsMatchRegexp( banner, "Basic realm=\"Usermin Server\"" ) ) {
			webmin = TRUE;
		}
		else {
			if(ContainsString( banner, "Usermin Server" ) || ContainsString( buf, ">Login to Usermin<" )){
				usermin = TRUE;
			}
		}
		vers = eregmatch( pattern: "Server\\s*:\\s*MiniServ/([0-9]\\.[0-9]+)", string: banner, icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		if( usermin ){
			set_kb_item( name: "usermin/installed", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:webmin:usermin:" );
			if(!cpe){
				cpe = "cpe:/a:webmin:usermin";
			}
			register_product( cpe: cpe, location: "/", port: port, service: "www" );
			log_message( data: build_detection_report( app: "Usermin", version: version, install: "/", cpe: cpe, concluded: concluded ), port: port );
		}
		else {
			set_kb_item( name: "webmin/installed", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:webmin:webmin:" );
			if(!cpe){
				cpe = "cpe:/a:webmin:webmin";
			}
			register_product( cpe: cpe, location: "/", port: port, service: "www" );
			log_message( data: build_detection_report( app: "Webmin", version: version, install: "/", cpe: cpe, concluded: concluded ), port: port );
		}
	}
}
exit( 0 );

