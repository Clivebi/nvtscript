if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11372" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2552 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-0248" );
	script_name( "HP-UX ftpd glob() Expansion STAT Buffer Overflow" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "ftp_writeable_directories.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/login", "ftp/writeable_dir", "ftp/banner/available" );
	script_tag( name: "solution", value: "- Upgrade your FTP server.

  - Consider removing directories writable by 'anonymous'." );
	script_tag( name: "summary", value: "Buffer overflow in FTP server in HPUX 11 and previous
  allows remote attackers to execute arbitrary commands by creating a long pathname and calling
  the STAT command, which uses glob to generate long strings." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
wri = get_kb_item( "ftp/writeable_dir" );
safe_checks = 0;
if(!login || !password || !wri || safe_checks()){
	safe_checks = 1;
}
if(safe_checks){
	banner = ftp_get_banner( port: port );
	if(banner){
		vuln = FALSE;
		if(ereg( pattern: "FTP server.*[vV]ersion[^0-9]*(10\\.[0-9]+|11\\.0)", string: banner )){
			vuln = TRUE;
		}
		if(vuln){
			security_message( port: port );
		}
	}
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	if(login && wri){
		if(ftp_log_in( socket: soc, user: login, pass: password )){
			c = NASLString( "CWD ", wri, "\\r\\n" );
			send( socket: soc, data: c );
			b = ftp_recv_line( socket: soc );
			if(!ereg( pattern: "^250.*", string: b )){
				exit( 0 );
			}
			mkd = NASLString( "MKD ", crap( 505 ), "\\r\\n" );
			mkdshort = NASLString( "MKD ", crap( 249 ), "\\r\\n" );
			stat = NASLString( "STAT ~/*\\r\\n" );
			send( socket: soc, data: mkd );
			b = ftp_recv_line( socket: soc );
			if(!ereg( pattern: "^257 .*", string: b )){
				send( socket: soc, data: mkdshort );
				b = ftp_recv_line( socket: soc );
				if(!ereg( pattern: "^257 .*", string: b )){
					exit( 0 );
				}
			}
			send( socket: soc, data: stat );
			b = ftp_recv_line( socket: soc );
			send( socket: soc, data: "RMD " + crap( 505 ) + "\r\n" );
			send( socket: soc, data: "RMD " + crap( 249 ) + "\r\n" );
			if( !b ){
				security_message( port: port );
				exit( 0 );
			}
			else {
				ftp_close( socket: soc );
			}
		}
	}
}

