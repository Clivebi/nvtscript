CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804214" );
	script_version( "$Revision: 13659 $" );
	script_bugtraq_id( 42029 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-07 19:55:38 +0530 (Tue, 07 Jan 2014)" );
	script_name( "TYPO3 Backend Open Redirection Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct phishing
  attacks." );
	script_tag( name: "vuldetect", value: "Send a Crafted HTTP GET request and check whether it is able to get sensitive
  information." );
	script_tag( name: "insight", value: "An error exists in Backend, which fails to sanitize 'redirect'
  parameter properly" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.1.14, 4.2.13, 4.3.4, 4.4.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to open redirection
  vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version before 4.1.14 and below, 4.2.0 to 4.2.13, 4.3.0 to 4.3.3 and 4.4.0" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40742/" );
	script_xref( name: "URL", value: "https://typo3.org/security/advisory/typo3-sa-2010-012/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("url_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("gvr_apps_auth_func.inc.sc");
if(!typoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(typoLoca = get_app_location( cpe: CPE, port: typoPort )){
	useragent = http_get_user_agent();
	host = http_host_name( port: typoPort );
	cookie = get_typo3_login_cookie( cinstall: typoLoca, tport: typoPort, chost: host );
	if(cookie){
		url = typoLoca + "/typo3/tce_file.php?redirect=http://www.example.com";
		req = NASLString( "GET ", url, " HTTP/1.0\\r\\n", "Host: " + host + "\\r\\n", "User-Agent: " + useragent + "\\r\\n", "Referer: http://" + host + url + "\\r\\n", "Connection: keep-alive\\r\\n", "Cookie: ", cookie, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n\\r\\n" );
		res = http_send_recv( port: typoPort, data: req, bodyonly: FALSE );
		get_typo3_logout( loc: typoLoca, lport: typoPort, lhost: host, lcookie: cookie );
		if(res && IsMatchRegexp( res, "HTTP/1.. 302" ) && ContainsString( res, "Expires: 0" ) && ContainsString( res, "Location: http://www.example.com" )){
			security_message( typoPort );
			exit( 0 );
		}
	}
}

