if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106122" );
	script_version( "2020-11-25T06:50:09+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 06:50:09 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-07-08 14:44:45 +0700 (Fri, 08 Jul 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SugarCRM Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of SugarCRM." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_suitecrm_detect.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.sugarcrm.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
if(get_kb_item( "salesagility/suitecrm/" + port + "/detected" )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/sugarcrm", "/SugarCRM", "/sugar", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php?action=Login&module=Users&login_module=Home&login_action=index";
	res = http_get_cache( port: port, item: url );
	res2 = http_get_cache( port: port, item: dir + "/" );
	if(ContainsString( res, "alt='Powered By SugarCRM'>" ) || ContainsString( res, "Set-Cookie: sugar_user_them" ) || ( IsMatchRegexp( res2, "<title>(.*)?SugarCRM</title>" ) && ContainsString( res2, "var parentIsSugar" ) )){
		version = "unknown";
		edition = "";
		url = dir + "/sugar_version.json";
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		ver = eregmatch( pattern: "\"sugar_version\":( )?\"([0-9.]+)\",", string: res );
		if(!isnull( ver[2] )){
			version = ver[2];
			concUrl = url;
		}
		ed = eregmatch( pattern: "\"sugar_flavor\":( )?\"([^\"]+)\",", string: res );
		if(!isnull( ed[2] )){
			edition = ed[2];
			set_kb_item( name: "sugarcrm/edition", value: edition );
		}
		set_kb_item( name: "sugarcrm/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sugarcrm:sugarcrm:" );
		if(!cpe){
			cpe = "cpe:/a:sugarcrm:sugarcrm";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SugarCRM " + edition, version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

