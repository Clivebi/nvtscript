if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11342" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2344 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2001-0361" );
	script_name( "PKCS 1 Version 1.5 Session Key Retrieval" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Xue Yong Zhi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_tag( name: "solution", value: "Patch and new version are available from SSH/OpenSSH." );
	script_tag( name: "summary", value: "You are running SSH protocol version 1.5." );
	script_tag( name: "impact", value: "This version allows a remote attacker to decrypt and/or
  alter traffic via an attack on PKCS#1 version 1.5 knows as a Bleichenbacher attack." );
	script_tag( name: "affected", value: "OpenSSH up to version 2.3.0, AppGate, and SSH Communications Security
  ssh-1 up to version 1.2.31 have the vulnerability present, although it may not be exploitable due to configurations." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner){
	exit( 0 );
}
if( ereg( string: banner, pattern: "SSH-.*-1\\.([01]|[01]\\..*|2\\.([0-9]|1[0-9]|2[0-9]|3[01]))[^0-9]*$", icase: TRUE ) ) {
	security_message( port: port );
}
else {
	if(ereg( pattern: ".*openssh[-_](1|2\\.([0-2]\\.|3\\.0)).*", string: banner, icase: TRUE )){
		security_message( port: port );
	}
}

