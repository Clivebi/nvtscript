if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14361" );
	script_version( "2020-05-05T09:44:01+0000" );
	script_tag( name: "last_modification", value: "2020-05-05 09:44:01 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0826" );
	script_bugtraq_id( 11015 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "NSS Library SSLv2 Challenge Overflow" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2004 Digital Defense" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_tls_version_get.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_tag( name: "solution", value: "Upgrade the remote service to use NSS 3.9.2 or newer." );
	script_tag( name: "summary", value: "The remote host seems to be using the Mozilla Network Security Services (NSS)
  Library, a set of libraries designed to support the development of security-enabled client/server application." );
	script_tag( name: "impact", value: "There seems to be a flaw in the remote version of this library, in the SSLv2 handling code, which may allow
  an attacker to cause a heap overflow and therefore execute arbitrary commands on the remote host. To exploit this
  flaw, an attacker would need to send a malformed SSLv2 'hello' message to the remote service." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("ssl_funcs.inc.sc");
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if( safe_checks() ){
	test = 0;
}
else {
	test = 1;
}
if(banner){
	if(egrep( pattern: ".*(Netscape.Enterprise|Sun-ONE).*", string: banner )){
		test++;
	}
}
if(!test){
	exit( 0 );
}
soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x80, 0x1c, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0xc0 ) + crap( length:16, data: "VT-Test" );
send( socket: soc, data: req );
res = recv( socket: soc, length: 64 );
close( soc );
if(strlen( res ) < 64){
	exit( 0 );
}
soc = open_sock_tcp( port: port, transport: ENCAPS_IP );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x80, 0x44, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x38, 0x07, 0x00, 0xc0 ) + crap( length:16, data: "VT-Test" ) + crap( length:40, data: "VULN" );
send( socket: soc, data: req );
res = recv( socket: soc, length: 2048 );
close( soc );
if(ContainsString( res, "VULN" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

