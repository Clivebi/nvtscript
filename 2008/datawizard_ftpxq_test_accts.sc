if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80053" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2006-5569" );
	script_bugtraq_id( 20721 );
	script_xref( name: "OSVDB", value: "30010" );
	script_name( "DataWizard FTPXQ Default Accounts" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ftpxq/detected" );
	script_tag( name: "solution", value: "Disable or change the password for any unnecessary user accounts." );
	script_tag( name: "summary", value: "The version of DataWizard FTPXQ that is installed on the remote host
  has one or more default accounts setup which can allow an attacker to read and/or write arbitrary files on the system." );
	script_xref( name: "URL", value: "http://attrition.org/pipermail/vim/2006-November/001107.html" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "FtpXQ FTP" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
n = 0;
acct[n] = "anonymous";
pass[n] = "";
n++;
acct[n] = "test";
pass[n] = "test";
file = "\\boot.ini";
contents = "";
info = "";
for(i = 0;i < max_index( acct );i++){
	login = acct[i];
	password = pass[i];
	if(ftp_authenticate( socket: soc, user: login, pass: password )){
		info += "  " + login + "/" + password + "\n";
		if(strlen( contents ) == 0){
			port2 = ftp_pasv( socket: soc );
			if(!port2){
				exit( 0 );
			}
			soc2 = open_sock_tcp( port: port2, transport: ENCAPS_IP );
			if(!soc2){
				exit( 0 );
			}
			attackreq = NASLString( "RETR ", file );
			send( socket: soc, data: NASLString( attackreq, "\\r\\n" ) );
			attackres = ftp_recv_line( socket: soc );
			if(egrep( string: attackres, pattern: "^(425|150) " )){
				attackres2 = ftp_recv_data( socket: soc2 );
				if(ContainsString( attackres2, "[boot loader]" )){
					contents = attackres2;
				}
			}
		}
	}
}
if(info){
	info = NASLString( "The remote version of FTPXQ has the following\\n", "default accounts enabled :\\n\\n", info );
	if(ContainsString( info, "test/test" )){
		info = NASLString( info, "\\n", "Note that the test account reportedly allows write access to the entire\\n", "filesystem, although the scanner did not attempt to verify this.\\n" );
	}
	if(contents){
		info = NASLString( info, "\\n", "In addition, the scanner was able to use one of the accounts to read ", file, " :\\n", "\\n", contents );
	}
	security_message( data: info, port: port );
}
ftp_close( socket: soc );

