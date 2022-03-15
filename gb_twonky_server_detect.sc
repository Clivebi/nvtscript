if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108003" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-09-27 12:00:00 +0200 (Tue, 27 Sep 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Twonky Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request
  to the server and attempts to extract the version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 9000 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	if(dir == "/webconfig"){
		continue;
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( buf, "<title>Twonky Server</title>" ) || ContainsString( buf, "<div id=\"twFooter\">" ) || ContainsString( buf, "<title>TwonkyServer Media Browser</title>" ) || IsMatchRegexp( buf, "PacketVideo(\\s|&nbsp;)Corporation\\.(\\s|&nbsp;)All(\\s|&nbsp;)rights(\\s|&nbsp;)reserved" ) || ContainsString( buf, "<title>TwonkyMedia</title>" ) || ContainsString( buf, "<title>TwonkyServer</title>" ) || ContainsString( buf, "<script type=\"text/javascript\" src=\"http://profile.twonky.com/tsconfig/js/onlinesvcs.js\" defer=\"defer\"></script>" ) || ( ContainsString( buf, "<li><a href=\"https://twitter.com/Twonky\" id=\"twSoctw\"" ) && ContainsString( buf, "<li><a href=\"http://www.facebook.com/Twonky\" id=\"twSocfb\"" ) )){
		version = "unknown";
		extra = "";
		url = dir + "/rpc/info_status";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		ver = eregmatch( pattern: "version\\|([0-9.\\-]+)", string: buf );
		if( IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ver[1] ){
			version = ver[1];
			concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 401" ) && ContainsString( buf, "Access to this page is restricted" )){
				extra = "The Web Console is protected by a password.";
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.\\-]+)", base: "cpe:/a:twonky:twonky_server:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:twonky:twonky_server";
		}
		set_kb_item( name: "www/" + port + "/twonky_server", value: version );
		set_kb_item( name: "twonky_server/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Twonky Server", version: version, install: install, extra: extra, cpe: cpe, concluded: ver[0], concludedUrl: concludedUrl ), port: port );
	}
}
exit( 0 );

