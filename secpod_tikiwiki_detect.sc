if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901001" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Tiki Wiki CMS Groupware Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://tiki.org/" );
	script_tag( name: "summary", value: "Detection of Tiki Wiki CMS Groupware.

  The script sends a connection request to the web server and attempts to
  detect Tiki Wiki CMS Groupware and its version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/tikiwiki", "/tiki", "/wiki", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/tiki-index.php", port: port );
	if(ContainsString( res, "content=\"Tiki Wiki CMS Groupware" ) || ContainsString( res, "/css/tiki_base.css\"" ) || ContainsString( res, "title=\"Tiki powered site\"" ) || ContainsString( res, "href=\"tiki-remind_password.php\"" ) || ContainsString( res, "This is Tikiwiki " ) || ContainsString( res, "\"lib/tiki-js.js\"" ) || ContainsString( res, "\"Tikiwiki powered site\"" ) || ContainsString( res, "img/tiki/tikilogo.png\"" )){
		version = "unknown";
		ver = eregmatch( pattern: "(Tiki[wW]iki v?|TikiWiki CMS/Groupware</a>\\s*v)([0-9.]+)", string: res );
		if( !isnull( ver[2] ) ){
			version = ver[2];
		}
		else {
			url = dir + "/README";
			res = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Tiki" )){
				ver = eregmatch( pattern: "[v|V]ersion ([0-9.]+)", string: res );
				if(!isnull( ver[1] )){
					version = ver[1];
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
		url = dir + "/tiki-install.php";
		res = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<title>Tiki Installer" )){
			extra = "The Tiki Installer is available at " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "TikiWiki/" + port + "/Ver", value: tmp_version );
		set_kb_item( name: "TikiWiki/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tiki:tikiwiki_cms/groupware:" );
		if(!cpe){
			cpe = "cpe:/a:tiki:tikiwiki_cms/groupware";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Tiki Wiki CMS Groupware", version: version, install: install, cpe: cpe, extra: extra, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

