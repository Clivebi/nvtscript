if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902661" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "SSL/TLS: Missing `secure` Cookie Attribute" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_tls_version_get.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "ssl_tls/port" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/SecureFlag" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc2965.txt" );
	script_xref( name: "URL", value: "https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OWASP-SM-002)" );
	script_tag( name: "summary", value: "The host is running a server with SSL/TLS and is prone to information
  disclosure vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to cookie is not using 'secure' attribute, which
  allows cookie to be passed to the server by the client over non-secure channels (http) and allows attacker
  to conduct session hijacking attacks." );
	script_tag( name: "affected", value: "Server with SSL/TLS." );
	script_tag( name: "solution", value: "Set the 'secure' attribute for any cookies that are sent over a SSL/TLS connection." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(get_port_transport( port ) < ENCAPS_SSLv23){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(res && ContainsString( res, "Set-Cookie:" )){
	cookies = egrep( string: res, pattern: "Set-Cookie:.*" );
	if(cookies){
		cookiesList = split( buffer: cookies, sep: "\n", keep: FALSE );
		vuln = FALSE;
		for cookie in cookiesList {
			if(!IsMatchRegexp( cookie, ";[ ]?[S|s]ecure?[^a-zA-Z0-9_-]?" )){
				pattern = "(Set-Cookie:.*=)([a-zA-Z0-9]+)(;.*)";
				if(eregmatch( pattern: pattern, string: cookie )){
					cookie = ereg_replace( string: cookie, pattern: pattern, replace: "\\1***replaced***\\3" );
				}
				vuln = TRUE;
				vulnCookies += cookie + "\n";
			}
		}
		if(vuln){
			report = "The cookies:\n\n" + vulnCookies + "\nare missing the \"secure\" attribute.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

