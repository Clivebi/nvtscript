if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111094" );
	script_version( "2021-06-16T13:40:04+0000" );
	script_tag( name: "last_modification", value: "2021-06-16 13:40:04 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-04-17 18:00:00 +0200 (Sun, 17 Apr 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "CKEditor Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://ckeditor.com/" );
	script_tag( name: "summary", value: "HTTP based detection of CKEditor." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
cgidirs = nasl_make_list_unique( "/", http_cgi_dirs( port: port ) );
subdirs = make_list( "/",
	 "/ckeditor",
	 "/editor",
	 "/admin/ckeditor",
	 "/sites/all/modules/ckeditor",
	 "/resources/ckeditor",
	 "/clientscript/ckeditor",
	 "/wp-content/plugins/ckeditor-for-wordpress/ckeditor" );
for cgidir in cgidirs {
	for subdir in subdirs {
		if(cgidir != "/" && subdir == "/"){
			subdir = "";
		}
		if(cgidir == "/"){
			cgidir = "";
		}
		dirs = nasl_make_list_unique( dirs, cgidir + subdir );
	}
}
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/ckeditor.js";
	buf = http_get_cache( item: url, port: port );
	url2 = dir + "/CHANGES.md";
	buf2 = http_get_cache( item: url2, port: port );
	if(( IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "CKSource" ) && ContainsString( buf, "CKEDITOR" ) ) || ( IsMatchRegexp( buf2, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf2, "CKEditor . Changelog" ) )){
		version = "unknown";
		ver = eregmatch( pattern: "version\\s*:\\s*[\"\']([0-9.]+)[\"\']", string: buf, icase: FALSE );
		if(!isnull( ver[1] )){
			version = ver[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown" && IsMatchRegexp( buf2, "^HTTP/1\\.[01] 200" )){
			ver = eregmatch( pattern: "## CKEditor ([0-9.]+)", string: buf2 );
			if(!isnull( ver[1] )){
				version = ver[1];
				conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ckeditor:ckeditor:" );
		if(!cpe){
			cpe = "cpe:/a:ckeditor:ckeditor";
		}
		set_kb_item( name: "ckeditor/detected", value: TRUE );
		set_kb_item( name: "ckeditor/http/detected", value: TRUE );
		set_kb_item( name: "ckeditor_or_fckeditor/detected", value: TRUE );
		set_kb_item( name: "ckeditor_or_fckeditor/http/detected", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "CKEditor", version: version, concluded: ver[0], concludedUrl: conclUrl, install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );

