if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113117" );
	script_version( "2021-09-27T13:38:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-27 13:38:53 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-02-20 13:31:37 +0100 (Tue, 20 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Kentico CMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Kentico CMS." );
	script_xref( name: "URL", value: "https://www.kentico.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(ContainsString( res, "<meta name=\"generator\" content=\"Kentico" ) || ( egrep( string: res, pattern: "^[Ss]et-[Cc]ookie\\s*:\\s*CMS(PreferredCulture|CsrfCookie|CurrentTheme|CookieLevel)=.+", icase: FALSE ) && egrep( string: res, pattern: "(<(link href|script src)=|\"imagesUrl\"\\s*:\\s*)\"[^\"]*/CMSPages/GetResource\\.ashx\\?", icase: FALSE ) )){
		version = "unknown";
		vers = eregmatch( string: res, pattern: "content=\"Kentico [CMS ]{0,4}[0-9.(betaR)?]+ \\(build ([0-9.]+)\\)", icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "kentico_cms/detected", value: TRUE );
		set_kb_item( name: "kentico_cms/http/detected", value: TRUE );
		register_and_report_cpe( app: "Kentico CMS", ver: version, concluded: vers[0], base: "cpe:/a:kentico:cms:", expr: "([0-9.]+)", insloc: install, conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ), regPort: port );
		exit( 0 );
	}
}
exit( 0 );

