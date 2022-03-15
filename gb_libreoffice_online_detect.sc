if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-07-05T06:08:17+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 06:08:17 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-09-15 09:00:00 +0200 (Thu, 15 Sep 2016)" );
	script_name( "LibreOffice Online Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9980 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://wiki.documentfoundation.org/Development/LibreOffice_Online" );
	script_tag( name: "summary", value: "HTTP based detection of LibreOffice Online." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9980 );
host = http_host_name( dont_add_port: TRUE );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/hosting/discovery";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( IsMatchRegexp( buf, "User-Agent\\s*:\\s*LOOLWSD (WOPI|HTTP) Agent" ) || ( ContainsString( buf, "wopi-discovery" ) && ContainsString( buf, "application/vnd." ) && ContainsString( buf, "loleaflet.html" ) ) )){
		version = "unknown";
		concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		reportUrl = "The following URLs were identified:\n\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n";
		for url in make_list( dir + "/dist/admin/admin.html",
			 dir + "/loleaflet/dist/admin/admin.html" ) {
			buf2 = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( buf2, "^HTTP/1\\.[01] 401" )){
				set_kb_item( name: "www/content/auth_required", value: TRUE );
				set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: url );
				reportUrl += http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n";
				break;
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/LibreOfficeOnline", value: tmp_version );
		set_kb_item( name: "LibreOfficeOnline/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:collabora:libreofficeonline:" );
		if(!cpe){
			cpe = "cpe:/a:collabora:libreofficeonline";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LibreOffice Online", version: version, install: install, cpe: cpe, concludedUrl: concludedUrl, extra: reportUrl ), port: port );
	}
}
exit( 0 );

