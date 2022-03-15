if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800810" );
	script_version( "2021-05-04T13:19:47+0000" );
	script_tag( name: "last_modification", value: "2021-05-04 13:19:47 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sun/Oracle Web Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "sun_oracle/web_servers/banner" );
	script_tag( name: "summary", value: "HTTP based detection of various Sun/Oracle Web Server products." );
	script_tag( name: "insight", value: "The following products are currently detected:

  - Oracle iPlanet Web Server

  - Sun ONE Web Server

  - Sun Java System Web Server" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "(Server|Www-authenticate|Proxy-agent)\\s*:.+" )){
	exit( 0 );
}
if(concl = egrep( string: banner, pattern: "^((Server|Proxy-agent)\\s*:\\s*Oracle-iPlanet-Web-Server|Www-authenticate\\s*:\\s*Basic realm=\"Oracle iPlanet Web Server\")", icase: TRUE )){
	oracle_iplanet_concluded = chomp( concl );
	is_oracle_iplanet = TRUE;
	found = TRUE;
}
if(concl = egrep( string: banner, pattern: "^Server\\s*:\\s*Sun-Java-System-Web-Server", icase: TRUE )){
	sun_java_system_concluded = chomp( concl );
	is_sun_java_system = TRUE;
	found = TRUE;
}
if(concl = egrep( string: banner, pattern: "^Server\\s*:\\s*Sun-ONE-Web-Server", icase: TRUE )){
	sun_one_concluded = chomp( concl );
	is_sun_one = TRUE;
	found = TRUE;
}
if(found){
	set_kb_item( name: "oracle_or_sun/web_server/detected", value: TRUE );
	set_kb_item( name: "oracle_or_sun/web_server/http/detected", value: TRUE );
	install = port + "/tcp";
	url = "/admingui/version/copyright";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Sun Java System Web Server" ) ) || is_sun_java_system){
		version = "unknown";
		vers = eregmatch( pattern: "Sun Java System Web Server ([0-9.]+)[^\r\n]*", string: res );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && vers[1]){
			version = vers[1];
			if(sun_java_system_concluded){
				sun_java_system_concluded += "\n";
			}
			sun_java_system_concluded += vers[0];
			concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "Sun-Java-System-Web-Server/([0-9.]+)", string: sun_java_system_concluded );
			if(vers[1]){
				version = vers[1];
			}
		}
		set_kb_item( name: "sun/java_system_web_server/detected", value: TRUE );
		set_kb_item( name: "sun/java_system_web_server/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:sun:java_system_web_server:" );
		if(!cpe){
			cpe = "cpe:/a:sun:java_system_web_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Sun Java System Web Server", version: version, install: install, cpe: cpe, concluded: sun_java_system_concluded, concludedUrl: concl_url ), port: port );
	}
	if(( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Oracle iPlanet Web Server" ) ) || is_oracle_iplanet){
		version = "unknown";
		vers = eregmatch( pattern: "Oracle iPlanet Web Server ([0-9.]+)[^\r\n]*", string: res, icase: FALSE );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && vers[1]){
			version = vers[1];
			if(oracle_iplanet_concluded){
				oracle_iplanet_concluded += "\n";
			}
			oracle_iplanet_concluded += vers[0];
			concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "Oracle-iPlanet-Web-Server/([0-9.]+)", string: oracle_iplanet_concluded );
			if(vers[1]){
				version = vers[1];
			}
		}
		set_kb_item( name: "oracle/iplanet_web_server/detected", value: TRUE );
		set_kb_item( name: "oracle/iplanet_web_server/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:oracle:iplanet_web_server:" );
		if(!cpe){
			cpe = "cpe:/a:oracle:iplanet_web_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Oracle iPlanet Web Server", version: version, install: install, cpe: cpe, concluded: oracle_iplanet_concluded, concludedUrl: concl_url ), port: port );
	}
	if(is_sun_one){
		version = "unknown";
		vers = eregmatch( pattern: "Sun-ONE-Web-Server/([0-9.]+)", string: sun_one_concluded );
		if(vers[1]){
			version = vers[1];
		}
		set_kb_item( name: "sun/one_web_server/detected", value: TRUE );
		set_kb_item( name: "sun/one_web_server/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sun:one_web_server:" );
		if(!cpe){
			cpe = "cpe:/a:sun:one_web_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Sun ONE Web Server", version: version, install: install, cpe: cpe, concluded: sun_one_concluded ), port: port );
	}
}
exit( 0 );

