if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112672" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-05 10:28:11 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "forma.lms Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether Forma Learning Management System
  is present on the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "http://www.formalms.org/" );
	exit( 0 );
}
CPE = "cpe:/a:formalms:formalms:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/formalms", http_cgi_dirs( port: port ) ) {
	location = dir;
	if(location == "/"){
		location = "";
	}
	url = location + "/";
	buf = http_get_cache( port: port, item: url );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "Copyright (c) forma.lms" ) || ContainsString( buf, "Powered by forma.lms CE" ) || ContainsString( buf, "<meta name=\"Generator\" content=\"www.formalms.org" ) || ContainsString( buf, "<link rel=\"Copyright\" href=\"http://www.formalms.org/copyright\"" ) )){
		set_kb_item( name: "formalms/detected", value: TRUE );
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "<meta name=\"Generator\" content=\"www\\.formalms\\.org ([0-9.]+)\" />" );
		if( !isnull( ver[1] ) ){
			version = ver[1];
			concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			vers_url = location + "/changelog.txt";
			vers_buf = http_get_cache( port: port, item: vers_url );
			ver = eregmatch( string: vers_buf, pattern: "(FORMA|forma\\.lms) ([0-9.]+)" );
			if(IsMatchRegexp( vers_buf, "^HTTP/1\\.[01] 200" ) && !isnull( ver[2] )){
				version = ver[2];
				concl_url = http_report_vuln_url( port: port, url: vers_url, url_only: TRUE );
			}
		}
		register_and_report_cpe( app: "Forma Learning Management System", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: dir, regPort: port, regService: "www", conclUrl: concl_url );
		exit( 0 );
	}
}
exit( 0 );

