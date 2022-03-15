if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11093" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3331, 3333 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-1109" );
	script_name( "EFTP installation directory disclosure " );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_require_keys( "ftp/login" );
	script_tag( name: "solution", value: "Update your FTP server." );
	script_tag( name: "summary", value: "The remote FTP server can be used to determine the
  installation directory by sending a request on an unexisting file." );
	script_tag( name: "impact", value: "An attacker may use this flaw to gain more knowledge about
  this host, such as its filesystem layout." );
	script_tag( name: "affected", value: "EFTP Version 2.0.7.337 is known to be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
cmd[0] = "GET";
cmd[1] = "MDTM";
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
port = ftp_get_port( default: 21 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
if(ftp_authenticate( socket: soc, user: login, pass: pass )){
	for(i = 0;i < 2;i++){
		vt_strings = get_vt_strings();
		req = NASLString( cmd[i], " ", vt_strings["lowercase_rand"], "\\r\\n" );
		send( socket: soc, data: req );
		r = ftp_recv_line( socket: soc );
		if(egrep( string: r, pattern: " '[C-Z]:\\\\'" )){
			security_message( port );
			ftp_close( socket: soc );
			exit( 0 );
		}
	}
}

