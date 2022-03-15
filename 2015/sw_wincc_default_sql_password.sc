if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111057" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2015-11-24 10:00:00 +0100 (Tue, 24 Nov 2015)" );
	script_bugtraq_id( 41753 );
	script_cve_id( "CVE-2010-2772" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Siemens WinCC MSSQL Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "This script is Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "mssqlserver_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/mssql", 1116 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Siemens WinCC MSSQL server has default credentials set." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the MS SQL service and try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials of WinCCAdmin/2WSXcde. and/or
  WinCCConnect/2WSXcder" );
	script_tag( name: "solution", value: "Update to V7.0 SP2 Update 1 (V 7.0.2.1) or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/41753" );
	script_xref( name: "URL", value: "http://scadastrangelove.blogspot.de/2012/07/wincc-default-password-7-years-long.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
pkt_hdr = raw_string( 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
pkt_pt2 = raw_string( 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x61, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x18, 0x81, 0xb8, 0x2c, 0x08, 0x03, 0x01, 0x06, 0x0a, 0x09, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x71, 0x75, 0x65, 0x6c, 0x64, 0x61, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
pkt_pt3 = raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4d, 0x53, 0x44, 0x42, 0x4c, 0x49, 0x42, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
pkt_lang = raw_string( 0x02, 0x01, 0x00, 0x47, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 );
func make_sql_login_pkt( username, password ){
	ulen = strlen( username );
	plen = strlen( password );
	upad = 30 - ulen;
	ppad = 30 - plen;
	ubuf = "";
	pbuf = "";
	nul = raw_string( 0x00 );
	if( ulen ){
		ublen = raw_string( ulen % 255 );
	}
	else {
		ublen = raw_string( 0x00 );
	}
	if( plen ){
		pblen = raw_string( plen % 255 );
	}
	else {
		pblen = raw_string( 0x00 );
	}
	ubuf = NASLString( username, crap( data: nul, length: upad ) );
	pbuf = NASLString( password, crap( data: nul, length: ppad ) );
	sql_packet = NASLString( pkt_hdr, ubuf, ublen, pbuf, pblen, pkt_pt2, pblen, pbuf, pkt_pt3 );
	return sql_packet;
}
port = get_kb_item( "Services/mssql" );
if(!port){
	port = 1116;
}
if(!get_port_state( port )){
	exit( 0 );
}
vuln = 0;
report = "It was possible to login using the following credentials:";
creds = make_array( "WinCCAdmin", "2WSXcde.", "WinCCConnect", "2WSXcder" );
for cred in keys( creds ) {
	soc = open_sock_tcp( port );
	if(soc){
		sql_packet = make_sql_login_pkt( username: cred, password: creds[cred] );
		send( socket: soc, data: sql_packet );
		send( socket: soc, data: pkt_lang );
		r = recv( socket: soc, length: 255 );
		close( soc );
		if(strlen( r ) > 10 && ord( r[8] ) == 0xE3){
			report += "\\n\\n" + cred + ":" + creds[cred] + "\\n";
			vuln = 1;
		}
	}
}
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

