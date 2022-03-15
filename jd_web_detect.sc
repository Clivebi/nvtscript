if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100301" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "JDownloader Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 8765, 9666 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://jdownloader.org" );
	script_tag( name: "summary", value: "JDownloader is running at this port. JDownloader is open
  source, platform independent and written completely in Java. It simplifies downloading files
  from One-Click-Hosters like Rapidshare.com or Megaupload.com." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8765 );
host = http_host_name( dont_add_port: TRUE );
url = "/";
buf = http_get_cache( item: url, port: port );
banner = http_get_remote_headers( port: port );
if( ContainsString( banner, "WWW-Authenticate: Basic realm=\"JDownloader" ) ){
	JD = TRUE;
	JD_WEBINTERFACE = TRUE;
	set_kb_item( name: "www/" + host + "/" + port + "/password_protected", value: TRUE );
	userpass = NASLString( "JD:JD" );
	userpass64 = base64( str: userpass );
	req = NASLString( "GET / HTTP/1.0\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n\\r\\n" );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(buf){
		if(ContainsString( buf, "JDownloader - WebInterface" )){
			DEFAULT_PW = TRUE;
			set_kb_item( name: "www/" + host + "/" + port + "/jdwebinterface/default_pw", value: TRUE );
			version = eregmatch( pattern: "Webinterface-([0-9]+)", string: buf );
		}
	}
}
else {
	if(ContainsString( buf, "JDownloader - WebInterface" )){
		JD = TRUE;
		JD_WEBINTERFACE = TRUE;
		JD_UNPROTECTED = TRUE;
		version = eregmatch( pattern: "Webinterface-([0-9]+)", string: buf );
	}
}
if(ContainsString( banner, "Server: jDownloader" )){
	concl = egrep( pattern: "^Server: jDownloader", string: banner );
	JD = TRUE;
	JD_WEBSERVER = TRUE;
	set_kb_item( name: "www/" + host + "/" + port + "/jdwebserver", value: TRUE );
}
if(JD){
	if(JD_WEBINTERFACE){
		if( version && !isnull( version[1] ) ){
			vers = version[1];
		}
		else {
			vers = "unknown";
		}
		set_kb_item( name: "www/" + host + "/" + port + "/jdwebinterface", value: vers );
		if( JD_UNPROTECTED ){
			info += NASLString( "\\nJDownloader Webinterface is *not* protected by password.\\n" );
		}
		else {
			if(DEFAULT_PW){
				info += NASLString( "\\nIt was possible to log in into the JDownloader Webinterface\\nby using 'JD' (the default username and password) as username and password.\\n" );
			}
		}
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:jdownloader:jdownloader_webgui:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:jdownloader:jdownloader_webgui";
		}
		register_product( cpe: cpe, location: url, port: port, service: "www" );
		report = build_detection_report( app: "JDownloader Webinterface", version: version, install: url, cpe: cpe, extra: info, concluded: version[0] );
	}
	if(JD_WEBSERVER){
		if(JD_WEBINTERFACE){
			report += "\n\n";
		}
		install = port + "/tcp";
		version = "unknown";
		cpe = "cpe:/a:jdownloader:jdownloader_webserver";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		report += build_detection_report( app: "JDownloader Webserver", version: version, install: install, cpe: cpe, concluded: chomp( concl ) );
	}
	log_message( port: port, data: report );
}
exit( 0 );

