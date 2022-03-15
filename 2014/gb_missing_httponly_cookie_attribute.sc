if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105925" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-09-01 16:00:00 +0100 (Mon, 01 Sep 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Missing `httpOnly` Cookie Attribute" );
	script_copyright( "Copyright (C) 2014 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/HttpOnly" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)" );
	script_tag( name: "summary", value: "The application is missing the 'httpOnly' cookie attribute" );
	script_tag( name: "vuldetect", value: "Check all cookies sent by the application for a missing 'httpOnly' attribute" );
	script_tag( name: "insight", value: "The flaw is due to a cookie is not using the 'httpOnly' attribute. This
  allows a cookie to be accessed by JavaScript which could lead to session hijacking attacks." );
	script_tag( name: "affected", value: "Application with session handling in cookies." );
	script_tag( name: "solution", value: "Set the 'httpOnly' attribute for any session cookie." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(buf && ContainsString( buf, "Set-Cookie:" )){
	cookies = egrep( string: buf, pattern: "Set-Cookie:.*" );
	if(cookies){
		cookiesList = split( buffer: cookies, sep: "\n", keep: FALSE );
		vuln = FALSE;
		for cookie in cookiesList {
			if(!IsMatchRegexp( cookie, ";[ ]?[H|h]ttp[O|o]nly?[^a-zA-Z0-9_-]?" )){
				pattern = "(Set-Cookie:.*=)([a-zA-Z0-9]+)(;.*)";
				if(eregmatch( pattern: pattern, string: cookie )){
					cookie = ereg_replace( string: cookie, pattern: pattern, replace: "\\1***replaced***\\3" );
				}
				vuln = TRUE;
				vulnCookies += cookie + "\n";
			}
		}
		if(vuln){
			report = "The cookies:\n\n" + vulnCookies + "\nare missing the \"httpOnly\" attribute.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

