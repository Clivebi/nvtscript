CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12293" );
	script_version( "2021-02-25T13:36:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10619, 12877 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2004-0493" );
	script_xref( name: "OSVDB", value: "7269" );
	script_name( "Apache HTTP Server Input Header Folding and mod_ssl ssl_io_filter_cleanup DoS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_xref( name: "URL", value: "http://www.guninski.com/httpd1.html" );
	script_tag( name: "summary", value: "The remote host appears to be running a version of Apache
  HTTP Server 2.x which is older than 2.0.50." );
	script_tag( name: "insight", value: "There is denial of service in apache httpd 2.0.x by sending a
  specially crafted HTTP request. It is possible to consume arbitrary
  amount of memory. On 64 bit systems with more than 4GB virtual memory
  this may lead to heap based buffer overflow.

  There is also a denial of service vulnerability in mod_ssl's
  ssl_io_filter_cleanup function. By sending a request to vulnerable
  server over SSL and closing the connection before the server can send
  a response, an attacker can cause a memory violation that crashes the
  server." );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.0.50 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "^Server:.*Apache(-AdvancedExtranetServer)?/2\\.0\\.(([0-9][^0-9])([0-3][0-9][^0-9])|(4[0-9][^0-9])).*", string: banner )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

