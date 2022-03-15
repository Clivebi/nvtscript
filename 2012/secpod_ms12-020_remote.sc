if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902818" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_cve_id( "CVE-2012-0002", "CVE-2012-0152" );
	script_bugtraq_id( 52353, 52354 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-03-16 16:21:31 +0100 (Fri, 16 Mar 2012)" );
	script_name( "Microsoft Remote Desktop Protocol Remote Code Execution Vulnerabilities (2671387) (Remote Check)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "ms_rdp_detect.sc" );
	script_require_ports( "Services/ms-wbt-server", 3389 );
	script_mandatory_keys( "msrdp/detected" );
	script_xref( name: "URL", value: "http://blog.binaryninjas.org/?p=58" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2671387" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1026790" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-020" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user or cause a denial of service condition." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaws are due to the way Remote Desktop Protocol accesses an
  object in memory that has been improperly initialized or has been deleted
  and the way RDP service processes the packets." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-020." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("bin.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 3389, proto: "ms-wbt-server" );
if(get_kb_item( "rdp/" + port + "/isxrdp" )){
	exit( 0 );
}
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
data = bin_pack( "!L", 0 );
rdp = bin_pack( "<BBS", 1, 0, 8 ) + data;
data = bin_pack(  "!SSB", 0, 0, 0 ) + rdp;
x224_1 = bin_pack(  "!BB", 14, 0xe0 ) + data;
tpkt = bin_pack(  "!BBS", 3, 0, 19 ) + x224_1;
send( socket: sock, data: tpkt );
res = recv( socket: sock, length: 8192 );
if(!res){
	close( sock );
	exit( 0 );
}
response = hexstr( res );
len = strlen( response );
if(( ( len == 22 ) && ( response != "0300000b06d00000123400" ) ) || ( ( len > 22 ) && ( substr( response, 0, 21 ) != "030000130ed00000123400" ) )){
	close( sock );
	exit( 0 );
}
data = bin_pack(  "!B", 0x80 );
x224_2 = bin_pack(  "!BB", 2, 0xf0 ) + data;
target_params = raw_string( "\\x02\\x01\\x22\\x02\\x01\\x20\\x02\\x01\\x00\\x02\\x01\\x01\\x02\\x01\\x00\\x02\\x01\\x01\\x02\\x02\\xff\\xff\\x02\\x01\\x02" );
min_params = raw_string( "\\x02\\x01\\x01\\x02\\x01\\x01\\x02\\x01\\x01\\x02\\x01\\x01\\x02\\x01\\x00\\x02\\x01\\x01\\x02\\x01\\xff\\x02\\x01\\x02" );
max_params = raw_string( "\\x02\\x01\\xff\\x02\\x01\\xff\\x02\\x01\\xff\\x02\\x01\\x01\\x02\\x01\\x00\\x02\\x01\\x01\\x02\\x02\\xff\\xff\\x02\\x01\\x02" );
mcs_data = raw_string( "\\x04\\x01\\x01\\x04\\x01\\x01\\x01\\x01\\xff\\x30" );
mcs_data += bin_pack(  "B", 25 ) + target_params + raw_string( "\\x30" );
mcs_data += bin_pack(  "B", 24 ) + min_params + raw_string( "\\x30" );
mcs_data += bin_pack(  "B", 25 ) + max_params + raw_string( "\\x04\\x00" );
mcs = raw_string( "\\x7f\\x65" ) + bin_pack(  "!B", 91 );
tmp = x224_2 + mcs + mcs_data;
data = bin_pack(  "!BBS", 3, 0, 101 ) + tmp;
send( socket: sock, data: data );
tmp = x224_2 + raw_string( "\\x28" );
data = bin_pack( "!BBS", 3, 0, 8 ) + tmp;
send( socket: sock, data: data );
response = recv( socket: sock, length: 8192 );
if(!response || strlen( response ) < 11){
	close( sock );
	exit( 0 );
}
ret = response[9] + response[10];
tmp_user = bin_unpack( format:"!S", blob: ret );
user1 = tmp_user["data"];
send( socket: sock, data: data );
response = recv( socket: sock, length: 8192 );
if(!response || strlen( response ) < 11){
	close( sock );
	exit( 0 );
}
ret = response[9] + response[10];
tmp_user = bin_unpack( format:"!S", blob: ret );
user2 = tmp_user["data"];
tmp = x224_2 + raw_string( "\\x38" );
data = tmp + bin_pack(  "!SS", user1[0], user2[0] + 1001 );
tpkt = bin_pack(  "!BBS", 3, 0, 12 ) + data;
send( socket: sock, data: tpkt );
response = recv( socket: sock, length: 8192 );
ret = response[7] + response[8];
if(ret == raw_string( "\\x3e\\x00" )){
	tmp = x224_2 + raw_string( "\\x38" ) + bin_pack(  "!SS", user2[0], user2[0] + 1001 );
	data = bin_pack(  "!BBS", 3, 0, 12 ) + tmp;
	send( socket: sock, data: data );
	ret = recv( socket: sock, length: 8192 );
	close( sock );
	security_message( port: port );
	exit( 0 );
}
close( sock );
exit( 99 );

