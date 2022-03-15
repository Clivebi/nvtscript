if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900015" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_bugtraq_id( 30370 );
	script_cve_id( "CVE-2007-5400" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_family( "Buffer overflow" );
	script_name( "RealPlayer SWF Frame Handling Buffer Overflow Vulnerability (Windows)" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/07252008_player/en/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/27620/" );
	script_tag( name: "summary", value: "This Remote host is running with RealPlayer, which is prone to
  buffer overflow vulnerability." );
	script_tag( name: "insight", value: "The flaw exists due to a design error in handling/parsing of frames
  in Shockwave Flash (SWF) files." );
	script_tag( name: "affected", value: "RealPlayer Version 10, 10.5 and 11 on Windows (All)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to the latest version available." );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to
  execute arbitrary code on a user's system." );
	exit( 0 );
}
require("smb_nt.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
realPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\realplay.exe", item: "Path" );
if(!realPath){
	exit( 0 );
}
realExe = realPath + "\\realplay.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: realExe );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: realExe );
name = kb_smb_name();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();
port = kb_smb_transport();
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = smb_session_request( soc: soc, remote: name );
if(!r){
	exit( 0 );
}
prot = smb_neg_prot( soc: soc );
if(!prot){
	exit( 0 );
}
r = smb_session_setup( soc: soc, login: login, password: pass, domain: domain, prot: prot );
if(!r){
	exit( 0 );
}
uid = session_extract_uid( reply: r );
if(!uid){
	exit( 0 );
}
r = smb_tconx( soc: soc, name: name, uid: uid, share: share );
if(!r){
	exit( 0 );
}
tid = tconx_extract_tid( reply: r );
if(!tid){
	exit( 0 );
}
fid = OpenAndX( socket: soc, uid: uid, tid: tid, file: file );
if(!fid){
	exit( 0 );
}
fsize = smb_get_file_size( socket: soc, uid: uid, tid: tid, fid: fid );
off = fsize - 90000;
for(;fsize != off;){
	data = ReadAndX( socket: soc, uid: uid, tid: tid, fid: fid, count: 16384, off: off );
	data = str_replace( find: raw_string( 0 ), replace: "", string: data );
	version = strstr( data, "ProductVersion" );
	if( !version ){
		off += 16383;
	}
	else {
		break;
	}
}
if(!version){
	exit( 0 );
}
v = "";
for(i = strlen( "ProductVersion" );i < strlen( version );i++){
	if( ( ord( version[i] ) < ord( "0" ) || ord( version[i] ) > ord( "9" ) ) && version[i] != "." ){
		break;
	}
	else {
		v += version[i];
	}
}
if(ereg( pattern: "^([0-5]\\..*|6\\.0\\.([0-9]\\..*|1?[01]\\..*|12\\.(10[4-9]?[0-9]?" + "|1[1-5][0-9][0-9]|16[0-5][0-9]|166[0-3]|1675|1698|1741)|" + "14\\.(73[89]|7[4-9][0-9]|80[0-2]|806)))$", string: v )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

