if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800779" );
	script_version( "2021-08-11T10:01:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 10:01:26 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenMairie Product Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of OpenMairie products." );
	script_xref( name: "URL", value: "http://www.openmairie.org" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
list = nasl_make_list_unique( "/openmairie_annuaire", "/Openmairie_Annuaire", "/openmairie_courrier", "/Openmairie_Courrier", "/openmairie_planning", "/Openmairie_Planning", "/openmairie_presse", "/Openmairie_Presse", "/openmairie_cominterne", "/Openmairie_Cominterne", "/openmairie_foncier", "/Openmairie_Foncier", "/openmairie_registreCIL", "/Openmairie_RegistreCIL", "/openmairie_cimetiere", "/Openmairie_Cimetiere", "/", "/scr", http_cgi_dirs( port: port ) );
for dir in list {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url1 = dir + "/index.php";
	url2 = dir + "/login.php";
	res1 = http_get_cache( port: port, item: url1 );
	res2 = http_get_cache( port: port, item: url2 );
	if(ContainsString( res1, ">Open Annuaire&" )){
		version = "unknown";
		vers = eregmatch( pattern: "Version&nbsp;([0-9.]+)", string: res1 );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "openmairie/products/detected", value: TRUE );
		set_kb_item( name: "openmairie/open_annuaire/detected", value: TRUE );
		set_kb_item( name: "openmairie/open_annuaire/http/detected", value: TRUE );
		concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openannuaire:" );
		if(!cpe){
			cpe = "cpe:/a:openmairie:openannuaire";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "OpenMairie Open Annuaire", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
	if(ContainsString( res1, ">Open Courrier&" ) || ContainsString( res2, "openCourrier<" )){
		version = "unknown";
		vers = eregmatch( pattern: "Version&nbsp;([0-9.]+)([a-z]*)", string: res1 );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
		}
		else {
			vers = eregmatch( pattern: "openCourrier Version ([0-9.]+)", string: res2 );
			if(!isnull( vers[1] )){
				version = vers[1];
				concUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
		}
		set_kb_item( name: "openmairie/products/detected", value: TRUE );
		set_kb_item( name: "openmairie/open_courrier/detected", value: TRUE );
		set_kb_item( name: "openmairie/open_courrier/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencourrier:" );
		if(!cpe){
			cpe = "cpe:/a:openmairie:opencourrier";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "OpenMairie Open Courrier", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
	if(ContainsString( res1, "presse" )){
		vers = eregmatch( pattern: "> V e r s i o n ([0-9.]+)", string: res1 );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			set_kb_item( name: "openmairie/products/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_presse/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_presse/http/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openpresse:" );
			if(!cpe){
				cpe = "cpe:/a:openmairie:openpresse";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenMairie Open Presse", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
	}
	if(ContainsString( res1, ">Open Planning&" )){
		vers = eregmatch( pattern: "Version&nbsp;([0-9.]+)", string: res1 );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			set_kb_item( name: "openmairie/products/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_planning/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_planning/http/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openplanning:" );
			if(!cpe){
				cpe = "cpe:/a:openmairie:openplanning";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenMairie Open Planning", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
	}
	if(ContainsString( res1, "Communication Interne" )){
		vers = eregmatch( pattern: "> V e r s i o n ([0-9.]+)", string: res1 );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			set_kb_item( name: "openmairie/products/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_cominterne/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_cominterne/http/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencominterne:" );
			if(!cpe){
				cpe = "cpe:/a:openmairie:oopencominterne";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenMairie Open Communication Interne", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
	}
	if(ContainsString( res1, ">opencimetiere" ) || IsMatchRegexp( res1, " openCimeti.re<" ) || IsMatchRegexp( res2, " openCimeti.re" )){
		version = "unknown";
		vers = eregmatch( pattern: "Version&nbsp;([0-9.]+)", string: res1 );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
		}
		else {
			vers = eregmatch( pattern: "openCimeti.re Version ([0-9.]+)", string: res1 );
			if( !isnull( vers[1] ) ){
				version = vers[1];
				concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			}
			else {
				vers = eregmatch( pattern: "openCimeti.re Version ([0-9.]+)", string: res2 );
				if(!isnull( vers[1] )){
					version = vers[1];
					concUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
				}
			}
		}
		set_kb_item( name: "openmairie/products/detected", value: TRUE );
		set_kb_item( name: "openmairie/open_cimetiere/detected", value: TRUE );
		set_kb_item( name: "openmairie/open_cimetiere/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencimetiere:" );
		if(!cpe){
			cpe = "cpe:/a:openmairie:opencimetiere";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "OpenMairie Open Communication Interne", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
	if(ContainsString( res1, ">Open Registre CIL&" )){
		vers = eregmatch( pattern: "Version&nbsp;([0-9.]+)", string: res1 );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			set_kb_item( name: "openmairie/products/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_registre/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_registre/http/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openregistrecil:" );
			if(!cpe){
				cpe = "cpe:/a:openmairie:openregistrecil";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenMairie Open Registre CIL", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
	}
	if(ContainsString( res1, ">openFoncier<" ) || ContainsString( res1, "Fonciere" )){
		vers = eregmatch( pattern: "Version&nbsp;([0-9.]+)", string: res1 );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
			set_kb_item( name: "openmairie/products/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_foncier/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_foncier/http/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openfoncier:" );
			if(!cpe){
				cpe = "cpe:/a:openmairie:openfoncier";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenMairie Open Foncier", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
		else {
			vers = eregmatch( pattern: ">version ((beta)?.?([0-9.]+))", string: res1 );
			if(!isnull( vers[1] )){
				version = ereg_replace( pattern: " ", string: vers[1], replace: "." );
				concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
				set_kb_item( name: "openmairie/products/detected", value: TRUE );
				set_kb_item( name: "openmairie/open_foncier/detected", value: TRUE );
				set_kb_item( name: "openmairie/open_foncier/http/detected", value: TRUE );
				cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openfoncier:" );
				if(!cpe){
					cpe = "cpe:/a:openmairie:openfoncier";
				}
				register_product( cpe: cpe, location: install, port: port, service: "www" );
				log_message( data: build_detection_report( app: "OpenMairie Open Foncier", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
			}
		}
	}
}
for dir in nasl_make_list_unique( "/openmairie_catalogue", "/Openmairie_Catalogue", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/doc/catalogue.html";
	res = http_get_cache( port: port, item: url );
	if(ContainsString( res, "OPENCATALOGUE" ) || IsMatchRegexp( res, "[Cc]atalogue" )){
		url = dir + "/index.php";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: "> V e r s i o n ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			set_kb_item( name: "openmairie/products/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_catalogue/detected", value: TRUE );
			set_kb_item( name: "openmairie/open_catalogue/http/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencatalogue:" );
			if(!cpe){
				cpe = "cpe:/a:openmairie:opencatalogue";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenMairie Open Catalogue", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		}
	}
}
exit( 0 );

