if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103875" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-01-09 18:50:23 +0100 (Thu, 09 Jan 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "QNAP NAS Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 8080 );
host = http_host_name( port: port );
useragent = http_get_user_agent();
for url in make_list( "/cgi-bin/login.html",
	 "/cgi-bin/html/login.html",
	 "/cgi-bin/authLogin.cgi" ) {
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( buf, "<title>Welcome to QNAP Turbo NAS" )){
		continue;
	}
	is_qts = FALSE;
	if(ContainsString( buf, "QTS_REMEMBER_ME" ) || ContainsString( buf, "QTS_SSL_LOGIN" )){
		set_kb_item( name: "qnap/qts", value: TRUE );
		is_qts = TRUE;
	}
	req = "POST /cgi-bin/authLogin.cgi HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n" + "Accept-Encoding: deflate\r\n" + "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" + "Referer: http://" + host + ":" + port + "/cgi-bin/login.html\r\n" + "Content-Length: 4\r\n" + "Connection: keep-alive\r\n" + "Pragma: no-cache\r\n" + "Cache-Control: no-cache\r\n" + "\r\n" + "&r=0";
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( buf, "QDocRoot" )){
		continue;
	}
	vers = "unknown";
	version = eregmatch( pattern: "<version><!\\[CDATA\\[([^]]+)\\]\\]></version>", string: buf );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	build = eregmatch( pattern: "<build><!\\[CDATA\\[([^]]+)\\]\\]></build>", string: buf );
	if(!isnull( build[1] )){
		build = build[1];
	}
	model = eregmatch( pattern: "<modelName><!\\[CDATA\\[([^]]+)\\]\\]></modelName>", string: buf );
	if(!isnull( model[1] )){
		model = model[1];
		cpe_model = tolower( str_replace( string: model, find: " ", replace: "_" ) );
	}
	displaymodel = eregmatch( pattern: "<displayModelName><!\\[CDATA\\[([^]]+)\\]\\]></displayModelName>", string: buf );
	if(!isnull( displaymodel[1] )){
		displaymodel = displaymodel[1];
	}
	cpe = "cpe:/h:qnap";
	if(cpe_model){
		cpe += ":" + cpe_model;
	}
	if(vers != "unknown"){
		cpe += ":" + vers;
	}
	if(build){
		cpe += "_" + build;
	}
	if(is_qts){
		os_cpe = "cpe:/o:qnap:qts";
		if(vers != "unknown"){
			os_cpe += ":" + vers;
		}
		os_register_and_report( os: "QNAP QTS", cpe: os_cpe, banner_type: "HTTP(s) Login Page", port: port, desc: "QNAP NAS Detection", runs_key: "unixoide" );
	}
	set_kb_item( name: "qnap/model", value: model );
	set_kb_item( name: "qnap/version", value: vers );
	set_kb_item( name: "qnap/build", value: build );
	set_kb_item( name: "qnap/port", value: port );
	set_kb_item( name: "qnap/dismodel", value: displaymodel );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "'QNAP " + model + "'", version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
	exit( 0 );
}
exit( 0 );

