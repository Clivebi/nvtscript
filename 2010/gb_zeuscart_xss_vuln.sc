CPE = "cpe:/a:zeuscart:zeuscart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801249" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ZeusCart 'search' Parameter Cross Site Scripting Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zeuscart_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zeuscart/installed" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=109" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35319/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/512885" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SECPOD_ZeusCart_XSS.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow the attacker to steal cookie-based authentication credentials
  and to launch other attacks." );
	script_tag( name: "affected", value: "ZeusCart Versions 3.0 and 2.3" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'search' parameter in a 'search' action which allows attacker to execute
  arbitrary HTML and script code in a user's browser session." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running ZeusCart and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(path == "/"){
	path = "";
}
if(!safe_checks()){
	url = path + "/";
	req = http_post( port: port, item: url, data: "%22%20style=x:expression(alert(document.cookie))><" );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "style=x:expression(alert(document.cookie))" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(!vers){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "3.0" ) || version_is_equal( version: vers, test_version: "2.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_url: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

