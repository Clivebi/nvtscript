if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10933" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3333 );
	script_cve_id( "CVE-2001-1109" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "EFTP tells if a given file exists" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 Michel Arboi" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/eftp/detected" );
	script_tag( name: "summary", value: "The remote FTP server can be used to determine if a given
  file exists on the remote host or not, by adding dot-dot-slashes in front of them." );
	script_tag( name: "insight", value: "For instance, it is possible to determine the presence
  of \\autoexec.bat by using the command SIZE or MDTM on ../../../../autoexec.bat" );
	script_tag( name: "impact", value: "An attacker may use this flaw to gain more knowledge about
  this host, such as its file layout. This flaw is specially useful when used with other vulnerabilities." );
	script_tag( name: "solution", value: "Update your EFTP server to 2.0.8.348 or change it." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
cmd[0] = "SIZE";
cmd[1] = "MDTM";
kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "EFTP " )){
	exit( 0 );
}
vuln = 0;
soc = open_sock_tcp( port );
if(soc){
	if( login && ftp_authenticate( socket: soc, user: login, pass: pass ) ){
		for(i = 0;cmd[i];i = i + 1){
			req = NASLString( cmd[i], " ../../../../../../autoexec.bat\\r\\n" );
			send( socket: soc, data: req );
			r = ftp_recv_line( socket: soc );
			if(ContainsString( r, "230 " )){
				vuln = vuln + 1;
			}
		}
	}
	else {
		r = ftp_recv_line( socket: soc );
		if(egrep( string: r, pattern: ".*EFTP version ([01]|2\\.0\\.[0-7])\\..*" )){
			vuln = 1;
		}
	}
	close( soc );
	if(vuln){
		security_message( port: port );
		exit( 0 );
	}
	exit( 99 );
}

