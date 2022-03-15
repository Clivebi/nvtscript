if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900005" );
	script_version( "2021-09-20T15:19:16+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 15:19:16 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_bugtraq_id( 30132 );
	script_cve_id( "CVE-2008-1447", "CVE-2008-1454" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_name( "Vulnerabilities in DNS Could Allow Spoofing (953230)" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "affected", value: "DNS Client/Server on Windows." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-037." );
	script_tag( name: "insight", value: "The flaws exist due to the DNS protocol fail to provide an
  adequate amount of entropy when performing DNS queries for Transaction ID and Source Port
  parameters that can be exploited to poison the DNS cache by inserting responses records into the
  DNS server or client cache." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "impact", value: "Successful execution of exploit could allow unauthenticated
  attackers to retrieve sensitive information and will redirect internet traffic to any server of
  the attacker's choosing." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30925/" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/800113" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Jul/1020438.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-037" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
func Get_FileVersion(  ){
	sysFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
	if(!sysFile){
		exit( 0 );
	}
	sysFile += "\\drivers\\Tcpip.sys";
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysFile );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysFile );
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
		close( soc );
		exit( 0 );
	}
	prot = smb_neg_prot( soc: soc );
	if(!prot){
		close( soc );
		exit( 0 );
	}
	r = smb_session_setup( soc: soc, login: login, password: pass, domain: domain, prot: prot );
	if(!r){
		close( soc );
		exit( 0 );
	}
	uid = session_extract_uid( reply: r );
	if(!uid){
		close( soc );
		exit( 0 );
	}
	r = smb_tconx( soc: soc, name: name, uid: uid, share: share );
	if(!r){
		close( soc );
		exit( 0 );
	}
	tid = tconx_extract_tid( reply: r );
	if(!tid){
		close( soc );
		exit( 0 );
	}
	fid = OpenAndX( socket: soc, uid: uid, tid: tid, file: file );
	if(!fid){
		close( soc );
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
	return ( v );
}
if(!registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\Dnscache" ) && !registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\DNS" )){
	exit( 0 );
}
if(hotfix_missing( name: "953230" ) == 0){
	exit( 0 );
}
fileVer = Get_FileVersion();
if(!fileVer){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(egrep( pattern: "^5\\.0?0\\.(([01]?[0-9]?[0-9]?[0-9]|2(0[0-9][0-9]|1([0-8][0-9]|9[0-4])))\\..*|2195\\.([0-6]?[0-9]?[0-9]?[0-9]|7(0[0-9][0-9]|1[0-5][0-9]|16[01])))$", string: fileVer )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
	exit( 99 );
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(egrep( pattern: "^5\\.0?1\\.(([01]?[0-9]?[0-9]?[0-9]|2([0-5][0-9][0-9]))\\..*|2600\\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-2][0-9][0-9]|3[0-8][0-9]|39[0-3])))$", string: fileVer )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			exit( 99 );
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(egrep( pattern: "^5\\.0?1\\.(([01]?[0-9]?[0-9]?[0-9]|2([0-5][0-9][0-9]))\\..*|2600\\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9][0-9]|6[01][0-9]|62[0-4])))$", string: fileVer )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
				exit( 99 );
			}
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(egrep( pattern: "^5\\.0?2\\.(([0-2]?[0-9]?[0-9]?[0-9]|3([0-6][0-9][0-9]|7[0-8][0-9]))\\..*|3790\\.([0-2]?[0-9]?[0-9]?[0-9]|30[0-9][0-9]|31([0-5][0-9]|60)))$", string: fileVer )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
				exit( 99 );
			}
			else {
				if(ContainsString( SP, "Service Pack 2" )){
					if(egrep( pattern: "^5\\.0?2\\.(([02]?[0-9]?[0-9]?[0-9]|3([0-6][0-9][0-9]|7[0-8][0-9]))\\..*|3790\\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|3(0[0-9]|1[0-7]))))$", string: fileVer )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
					exit( 99 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
exit( 99 );

