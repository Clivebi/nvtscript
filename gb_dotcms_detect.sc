if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106114" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-05 08:55:18 +0700 (Tue, 05 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "dotCMS Detection" );
	script_tag( name: "summary", value: "Detection of dotCMS

  The script sends a connection request to the server and attempts to detect the presence of dotCMS and to
  extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://dotcms.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/dotcms", "/dotCMS", "/dotAdmin", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for url in nasl_make_list_unique( dir + "/html/portal/login.jsp", dir + "/application/login/login.html" ) {
		found = FALSE;
		version = "unknown";
		res = http_get_cache( port: port, item: url );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<title>dotCMS : Enterprise Web Content Management</title>" ) && ContainsString( res, "modulePaths: { dotcms:" )){
			found = TRUE;
			for(i = 7;i > 0;i -= 2){
				ver = eregmatch( pattern: "<br />.*(COMMUNITY|ENTERPRISE) (EDITION|PROFESSIONAL).*([0-9\\.]{" + i + "})<br/>", string: res );
				if(!isnull( ver[3] )){
					version = ver[3];
					concUrl = url;
					break;
				}
			}
			if(version == "unknown"){
				ver = eregmatch( pattern: "\\.(css|js|jsp)\\?b=([0-9\\.]+)\\\";", string: res );
				version = ver[2];
				concUrl = url;
			}
		}
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "dotcms" ) || ContainsString( res, "dotCMS" ) ) && ( ContainsString( res, "<meta name=\"application-name\" content=\"dotCMS dotcms.com\"" ) || ContainsString( res, "document.getElementById('macro-login-user-name').value = 'bill@dotcms.com';" ) || ContainsString( res, "<link rel=\"stylesheet\" href=\"/DOTLESS/application/themes/quest/less/main.css\">" ) || ContainsString( res, "<link rel=\"shortcut icon\" href=\"http://dotcms.com/favicon.ico\" type=\"image/x-icon\">" ) || ContainsString( res, "href=\"http://dotcms.com/plugins/single-sign-on-using-oauth2\"" ) || ContainsString( res, "Powered by dotCMS" ) || ContainsString( res, "<a class=\"dropdown-item\" href=\"/dotCMS/logout\"" ) )){
			found = TRUE;
			url = "/api/v1/loginform";
			data = "{\"messagesKey\":[\"Login\",\"email-address\",\"user-id\",\"password\",\"remember-me\",\"sign-in\"," + "\"get-new-password\",\"cancel\",\"Server\",\"error.form.mandatory\"," + "\"angular.login.component.community.licence.message\",\"reset-password-success\"," + "\"a-new-password-has-been-sent-to-x\"],\"language\":\"\",\"country\":\"\"}";
			req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/json" ) );
			res = http_keepalive_send_recv( port: port, data: req );
			ver = eregmatch( pattern: "\"version\":\"([0-9.]+)", string: res );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
			concUrl = url;
		}
		if(found){
			set_kb_item( name: "dotCMS/installed", value: TRUE );
			if(version != "unknown"){
				set_kb_item( name: "dotCMS/version", value: version );
			}
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dotcms:dotcms:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:dotcms:dotcms";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "dotCMS", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concUrl ), port: port );
			exit( 0 );
		}
	}
	for location in nasl_make_list_unique( "/", "/api", "/api/v1", "/api/v2", "/api/v3", http_cgi_dirs( port: port ) ) {
		dir = location;
		if(dir == "/"){
			dir = "";
		}
		url = dir + "/appconfiguration";
		buf = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( buf, "dotcms.websocket" )){
			set_kb_item( name: "dotCMS/installed", value: TRUE );
			version = "unknown";
			ver = eregmatch( string: buf, pattern: "\"version\":\"([0-9.]+)\"", icase: TRUE );
			if(!isnull( ver[1] )){
				version = ver[1];
				set_kb_item( name: "dotCMS/version", value: version );
			}
			register_and_report_cpe( app: "dotCMS", ver: version, concluded: ver[0], base: "cpe:/a:dotcms:dotcms:", expr: "([0-9.]+)", insloc: location, regPort: port, conclUrl: url );
			exit( 0 );
		}
	}
}
exit( 0 );

