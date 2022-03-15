if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106458" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-09 11:42:44 +0700 (Fri, 09 Dec 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "MODX Evolution/Revolution CMS Detection" );
	script_tag( name: "summary", value: "Detection of MODX Evolution/Revolution CMS

  The script sends a connection request to the server and attempts to detect the presence of MODX Evolution/Revolution
  CMS and to extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/modx", "/evolution", "/revolution", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/manager/index.php";
	res = http_get_cache( port: port, item: url );
	if(( ContainsString( res, "http://modx.com/about/" ) && ContainsString( res, "modx-login-username-reset" ) ) || ( ContainsString( res, "http://modx.com/" ) && ContainsString( res, ">MODX</a>. <strong>MODX</strong>" ) ) || ContainsString( res, "<title>MODX-CMF-Manager-Login" ) || ContainsString( res, "(MODX CMF Manager Login)</title>" ) || ContainsString( res, "<title>MODx CMF Manager Login</title>" ) || ContainsString( res, "<title>MODx CMF Manager-Login</title>" )){
		version = "unknown";
		base_cpe = "cpe:/a:modx:unknown";
		cms_type = "Unknown Variant";
		conclUrl = NULL;
		url = dir + "/core/docs/changelog.txt";
		req = http_get( port: port, item: url );
		res2 = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "MOD(X|x) Revolution ([0-9.]+(-rc[1-9]+)?)", string: res2 );
		if( !isnull( vers[2] ) ){
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			version = vers[2];
			base_cpe = "cpe:/a:modx:revolution";
			cms_type = "Revolution";
		}
		else {
			url = dir + "/assets/docs/changelog.txt";
			req = http_get( port: port, item: url );
			res2 = http_keepalive_send_recv( port: port, data: req );
			vers = eregmatch( pattern: "MODX Evolution ([0-9.]+(-rc[1-9]+)?)", string: res2 );
			if(!isnull( vers[1] )){
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				version = vers[1];
				base_cpe = "cpe:/a:modx:evolution";
				cms_type = "Evolution";
			}
		}
		if(cms_type == "Unknown Variant"){
			if( ContainsString( res, "MODX Revolution</title>" ) || ContainsString( res, "<h2>MODx Revolution</h2>" ) ){
				base_cpe = "cpe:/a:modx:revolution";
				cms_type = "Revolution";
			}
			else {
				url = dir + "/README.md";
				req = http_get( port: port, item: url );
				res2 = http_keepalive_send_recv( port: port, data: req );
				if( ContainsString( res2, "# MODX Evolution" ) ){
					base_cpe = "cpe:/a:modx:evolution";
					cms_type = "Evolution";
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
				else {
					if(ContainsString( res, ">MODx CMF Team</a>" )){
						base_cpe = "cpe:/a:modx:evolution";
						cms_type = "Evolution";
					}
				}
			}
		}
		set_kb_item( name: "modx_cms/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+(-rc[1-9]+)?)", base: base_cpe + ":" );
		if(!cpe){
			cpe = base_cpe;
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "MODX " + cms_type + " CMS", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

