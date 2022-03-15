if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801228" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)" );
	script_cve_id( "CVE-2010-2620" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Open-FTPD Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/13932" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40284" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/open-ftpd/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain
  security restrictions and execute FTP commands without any authentication." );
	script_tag( name: "affected", value: "Open&Compact FTP Server (Open-FTPD) Version 1.2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to access not being restricted to various FTP
  commands before a user is properly authenticated. This can be exploited to execute FTP commands
  without any authentication." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Open&Compact FTP Server (Open-FTPD) and is
  prone to authentication bypass vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "Gabriel's FTP Server" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
ftp_send_cmd( socket: soc, cmd: "LIST" );
result = ftp_recv_listing( socket: soc );
close( soc );
if(ContainsString( result, "226 Transfer Complete" )){
	security_message( port: port );
	exit( 0 );
}

