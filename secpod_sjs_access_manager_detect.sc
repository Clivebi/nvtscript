if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900194" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sun Java System Access Manager Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Access Manager." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in make_list( "/",
	 "/amserver" ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/UI/Login.jsp", port: port );
	if(egrep( pattern: "Sun Java System Access Manager .*", string: res ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: res )){
		version = "unknown";
		set_kb_item( name: "Sun/JavaSysAccessManger/detected", value: TRUE );
		set_kb_item( name: "JavaSysAccessManger_or_OracleOpenSSO/detected", value: TRUE );
		vers = eregmatch( pattern: "X-DSAMEVersion: ([0-9]\\.[0-9.]+(.?[a-zQ0-9]+)?)", string: res );
		if(!isnull( vers[1] )){
			concluded = vers[0];
			vers = ereg_replace( pattern: " ", string: vers[1], replace: "." );
			tmp_version = vers + " under " + install;
			set_kb_item( name: "www/" + port + "/Sun/JavaSysAccessManger", value: tmp_version );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:sun:java_system_access_manager:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:sun:java_system_access_manager";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Sun Java System Access Manager", version: version, install: install, cpe: cpe, concluded: concluded ), port: port );
		exit( 0 );
	}
}
exit( 0 );

