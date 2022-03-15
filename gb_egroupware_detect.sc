if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100823" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-24 14:46:08 +0200 (Fri, 24 Sep 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "EGroupware Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of EGroupware.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/egw", "/egroupware", "/groupware", "/eGroupware/egroupware", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	buf = http_get_cache( item: url, port: port );
	if(isnull( buf )){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>eGroupWare [Login]</title>" ) || ContainsString( buf, "<title>EGroupware [Login]</title>" ) || ContainsString( buf, "<meta name=\"author\" content=\"EGroupware" ) || ContainsString( buf, "<meta name=\"keywords\" content=\"EGroupware" ) || ContainsString( buf, "<meta name=\"description\" content=\"EGroupware" ) || ContainsString( buf, "<meta name=\"copyright\" content=\"EGroupware" ) || ( ContainsString( buf, "<div id=\"divLogo\"><a href=" ) && ContainsString( buf, "<!-- BEGIN registration -->" ) && ContainsString( buf, "<!-- END registration -->" ) ) )){
		vers = "unknown";
		url = dir + "/setup/index.php";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		version = eregmatch( string: buf, pattern: "version ([0-9.]+)", icase: TRUE );
		if( !isnull( version[1] ) ){
			concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			vers = chomp( version[1] );
		}
		else {
			url = dir + "/status.php";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			version = eregmatch( string: buf, pattern: "versionstring\":\"EGroupware ([0-9.]+)\"", icase: TRUE );
			if(!isnull( version[1] )){
				concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				vers = version[1];
			}
		}
		if(vers == "unknown" || IsMatchRegexp( vers, "^16" )){
			url = dir + "/doc/rpm-build/debian.changes";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			version = eregmatch( pattern: "egroupware-epl \\(([0-9.]+)\\)", string: buf );
			if(!isnull( version[1] )){
				concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				vers = version[1];
			}
		}
		tmp_version = vers + " under " + install;
		set_kb_item( name: "www/" + port + "/egroupware", value: tmp_version );
		set_kb_item( name: "egroupware/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:egroupware:egroupware:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:egroupware:egroupware";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "EGroupware", version: vers, install: install, cpe: cpe, concluded: version[0], concludedUrl: concludedUrl ), port: port );
	}
}
exit( 0 );

