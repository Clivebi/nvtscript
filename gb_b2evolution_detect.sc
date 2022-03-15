if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106534" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-01-20 12:59:58 +0700 (Fri, 20 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "b2evolution Detection" );
	script_tag( name: "summary", value: "Detection of b2evolution CMS

  The script sends a HTTP connection request to the server and attempts to detect the presence of b2evolution CMS
  and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://b2evolution.net/" );
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
for dir in nasl_make_list_unique( "/", "/b2evolution", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url1 = dir + "/admin.php";
	url2 = dir + "/blogs/admin.php";
	url3 = dir + "/evoadm.php";
	url4 = dir + "/index.php";
	url5 = dir + "/login.php";
	res1 = http_get_cache( port: port, item: url1 );
	res2 = http_get_cache( port: port, item: url2 );
	res3 = http_get_cache( port: port, item: url3 );
	res4 = http_get_cache( port: port, item: url4 );
	res5 = http_get_cache( port: port, item: url5 );
	if(( ContainsString( res1, "://b2evolution.net/" ) && ( ContainsString( res1, "<title>Log in to your account</title>" ) || ContainsString( res1, "visit b2evolution's website" ) ) && ( ContainsString( res1, "pwd_salt" ) || ContainsString( res1, "pwd_hashed" ) ) ) || ( ContainsString( res2, "://b2evolution.net/" ) && ( ContainsString( res2, "<title>Log in to your account</title>" ) || ContainsString( res2, "visit b2evolution's website" ) ) && ( ContainsString( res2, "pwd_salt" ) || ContainsString( res2, "pwd_hashed" ) ) ) || ( ContainsString( res3, "://b2evolution.net/" ) && ( ContainsString( res3, "<title>Log in to your account</title>" ) || ContainsString( res3, "visit b2evolution's website" ) ) && ( ContainsString( res3, "pwd_salt" ) || ContainsString( res3, "pwd_hashed" ) ) ) || ContainsString( res4, "name=\"generator\" content=\"b2evolution" ) || ContainsString( res5, "name=\"generator\" content=\"b2evolution" )){
		version = "unknown";
		vers = eregmatch( pattern: "<strong>b2evolution ([0-9.]+)", string: res1 );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "b2evolution/version", value: version );
			conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "<strong>b2evolution ([0-9.]+)", string: res2 );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "b2evolution/version", value: version );
				conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "<strong>b2evolution ([0-9.]+)", string: res3 );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "b2evolution/version", value: version );
				conclUrl = http_report_vuln_url( port: port, url: url3, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "content=\"b2evolution ([0-9.]+)", string: res4 );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "b2evolution/version", value: version );
				conclUrl = http_report_vuln_url( port: port, url: url4, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "content=\"b2evolution ([0-9.]+)", string: res5 );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "b2evolution/version", value: version );
				conclUrl = http_report_vuln_url( port: port, url: url5, url_only: TRUE );
			}
		}
		set_kb_item( name: "b2evolution/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:b2evolution:b2evolution:" );
		if(!cpe){
			cpe = "cpe:/a:b2evolution:b2evolution";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "b2evolution", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

