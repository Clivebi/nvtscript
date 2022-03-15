if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113557" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-08 15:48:22 +0200 (Fri, 08 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Forcepoint Email Security Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether Forcepoint Email Security
  is present on the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.forcepoint.com/product/email-security" );
	exit( 0 );
}
CPE = "cpe:/a:forcepoint:email_security:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	location = dir;
	if(location == "/"){
		location = "";
	}
	url = location + "/pem/login/pages/login.jsf";
	buf = http_get_cache( port: port, item: url );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "<title>Forcepoint Email Security" )){
		set_kb_item( name: "forcepoint/email_security/detected", value: TRUE );
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "&nbsp;Version&nbsp;([0-9.]+)" );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		register_and_report_cpe( app: "Forcepoint Email Security", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: dir, regPort: port, regService: "www", conclUrl: url );
	}
}
exit( 0 );

