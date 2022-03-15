if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112082" );
	script_version( "2021-02-16T11:35:40+0000" );
	script_tag( name: "last_modification", value: "2021-02-16 11:35:40 +0000 (Tue, 16 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-10-16 10:50:45 +0200 (Mon, 16 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "EPESI Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of EPESI." );
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
found = FALSE;
for dir in nasl_make_list_unique( "/", "/epesi", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	app_url = dir + "/index.php";
	buf = http_get_cache( item: app_url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ( ContainsString( buf, "#epesiStatus" ) && ContainsString( buf, "<div id=\"epesiStatus\">" ) ) || ContainsString( buf, "<span id=\"epesiStatusText\">Starting epesi ...</span>" ) || ( ContainsString( buf, "<script type=\"text/javascript\">Epesi.init" ) && ContainsString( buf, "<noscript>Please enable JavaScript in your browser and let EPESI work!</noscript>" ) ) )){
		found = TRUE;
		vers = "unknown";
		ver_url = dir + "/docs/CHANGELOG.md";
		req = http_get( item: ver_url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(IsMatchRegexp( buf, "EPESI CHANGELOG" )){
			if(( version = eregmatch( string: buf, pattern: "RELEASE ([0-9.]+)-([0-9]+)", icase: TRUE ) ) || ( version = eregmatch( string: buf, pattern: "RELEASE ([0-9.]+)-rev[0-9]+ \\(([0-9]+)\\)", icase: TRUE ) )){
				concludedUrl = http_report_vuln_url( port: port, url: ver_url, url_only: TRUE );
				vers = chomp( version[1] );
				rev = chomp( version[2] );
				set_kb_item( name: "epesi/revision", value: rev );
			}
		}
		if(found){
			set_kb_item( name: "epesi/installed", value: TRUE );
			cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:telaxus:epesi:" );
			if(!cpe){
				cpe = "cpe:/a:telaxus:epesi";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			if(rev){
				extra = "rev" + rev;
			}
			log_message( data: build_detection_report( app: "EPESI", version: vers, install: install, cpe: cpe, concluded: version[0], concludedUrl: concludedUrl, extra: extra ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

