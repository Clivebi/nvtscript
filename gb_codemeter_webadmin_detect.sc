if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801988" );
	script_version( "2020-09-18T14:34:39+0000" );
	script_tag( name: "last_modification", value: "2020-09-18 14:34:39 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "WIBU-SYSTEMS CodeMeter WebAdmin Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 22350, 22352, 22353 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether WIBU-SYSTEMS CodeMeter WebAdmin is
  present on the target system and if so, tries to figure out the installed version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
func report_runtime( port, url, location, version, concluded ){
	var port, url, location, version;
	var concluded;
	concluded = http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n  " + concluded;
	set_kb_item( name: "wibu/codemeter_runtime/detected", value: TRUE );
	set_kb_item( name: "wibu/codemeter_runtime/http/port", value: port );
	set_kb_item( name: "wibu/codemeter_runtime/http/" + port + "/detected", value: TRUE );
	set_kb_item( name: "wibu/codemeter_runtime/http/" + port + "/location", value: location );
	set_kb_item( name: "wibu/codemeter_runtime/http/" + port + "/version", value: version );
	set_kb_item( name: "wibu/codemeter_runtime/http/" + port + "/concluded", value: concluded );
}
ports = http_get_ports( default_port_list: make_list( 22350,
	 22352,
	 22353 ) );
for port in ports {
	banner = http_get_remote_headers( port: port );
	url = "/home.html";
	res = http_get_cache( item: url, port: port );
	url2 = "/index.html";
	res2 = http_get_cache( item: url2, port: port );
	url3 = "/dashboard.html";
	res3 = http_get_cache( item: url3, port: port );
	if(ContainsString( res, "<title>CodeMeter | WebAdmin</title>" ) || ContainsString( res, "WIBU-SYSTEMS HTML Served Page" ) || ContainsString( res2, "<title>CodeMeter | WebAdmin</title>" ) || ContainsString( res2, "WIBU-SYSTEMS HTML Served Page" ) || ( ContainsString( res3, ">WebAdmin | " ) && ContainsString( res3, "WIBU-SYSTEMS" ) ) || ContainsString( res3, ">The access to the CodeMeter Server was not permitted<" ) || ContainsString( banner, "Server: WIBU-SYSTEMS HTTP Server" )){
		version = "unknown";
		install = "/";
		conclUrl = "";
		ver = eregmatch( pattern: "WebAdmin Version[^\\n]+Version ([0-9.]+)", string: res );
		if(ver[1]){
			version = ver[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: ">WebAdmin Version[^\n]+>([0-9.]+)<", string: res2 );
			if(ver[1]){
				version = ver[1];
				conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
		}
		runtime_vers = eregmatch( pattern: ">Runtime Version[^\n]+\n[^\n]+(([0-9.]+)([a-z]+)?)<", string: res2 );
		if( runtime_vers[1] ){
			report_runtime( port: port, url: url2, location: install, version: runtime_vers[1], concluded: runtime_vers[0] );
		}
		else {
			runtime_vers = eregmatch( pattern: ">Runtime Version[^\n]+\n[^\n]+>(([0-9.]+)([a-z]+)?)<", string: res3 );
			if(runtime_vers[1]){
				report_runtime( port: port, url: url3, location: install, version: runtime_vers[1], concluded: runtime_vers[0] );
			}
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: ">WebAdmin Version[^\n]+>([0-9.]+)<", string: res3 );
			if(ver[1]){
				version = ver[1];
				conclUrl = http_report_vuln_url( port: port, url: url3, url_only: TRUE );
			}
		}
		set_kb_item( name: "wibu/codemeter_webadmin/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:wibu:codemeter_webadmin:" );
		if(!cpe){
			cpe = "cpe:/a:wibu:codemeter_webadmin";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "WIBU-SYSTEMS CodeMeter WebAdmin", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

