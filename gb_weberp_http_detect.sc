if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145300" );
	script_version( "2021-02-24T08:59:37+0000" );
	script_tag( name: "last_modification", value: "2021-02-24 08:59:37 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-03 09:25:27 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "webERP Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of webERP." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.weberp.org/" );
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
for dir in nasl_make_list_unique( "/", "/weberp", "/webERP", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/index.php" );
	if(ContainsString( res, "<title>webERP Login" ) && ContainsString( res, "name=\"CompanyNameField\"" )){
		version = "unknown";
		url = dir + "/doc/CHANGELOG.md";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: "## \\[v([0-9a-z.]+)\\]", string: res, icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
			concluded = vers[0];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			url = dir + "/doc/Change.log";
			res = http_get_cache( port: port, item: url );
			vers = eregmatch( pattern: "(Release|Version) ([0-9a-z.]+)", string: res, icase: TRUE );
			if(!isnull( vers[2] )){
				version = vers[2];
				concluded = vers[0];
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/sql/mysql/country_sql/demo.sql";
			req = http_get( port: port, item: url );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			vers = eregmatch( pattern: "'VersionNumber','([0-9a-z.]+)'", string: res, icase: TRUE );
			if(!isnull( vers[1] )){
				version = vers[1];
				concluded = vers[0];
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		set_kb_item( name: "weberp/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:weberp:weberp:" );
		if(!cpe){
			cpe = "cpe:/a:weberp:weberp";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "webERP", version: version, install: install, cpe: cpe, concluded: concluded, concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

