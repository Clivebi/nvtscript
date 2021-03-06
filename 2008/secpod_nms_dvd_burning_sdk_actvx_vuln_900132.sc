if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900132" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-26 07:36:49 +0200 (Fri, 26 Sep 2008)" );
	script_cve_id( "CVE-2008-4342" );
	script_bugtraq_id( 31374 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "General" );
	script_name( "NuMedia Soft DVD Burning SDK Activex Control Remote Code Execution Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://cdburnerxp.se/en/home" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6491" );
	script_tag( name: "summary", value: "The host is installed CDBurnerXP, which is prone to ActiveX control
  based remote code execution vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error in validating/sanitizing the input data
  sent to NMSDVDX.dll file." );
	script_tag( name: "affected", value: "CDBurnerXP versions 4.2.1.976 and prior on all platform" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to CDBurnerXP Version 4.3.2 or later." );
	script_tag( name: "impact", value: "Exploitation will cause Internet Explorer to restrict the webpage
  from running scripts and could overwrite files with arbitrary content." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
cdBurnerXpPath = registry_get_sz( item: "ImagePath", key: "SYSTEM\\ControlSet001\\Services\\NMSAccessU" );
if(!cdBurnerXpPath){
	exit( 0 );
}
cdBurnerXpPath = cdBurnerXpPath - "\\NMSAccessU.exe" + "\\cdbxpp.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: cdBurnerXpPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: cdBurnerXpPath );
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
cdBurnerXpVer = GetVersion( socket: soc, uid: uid, tid: tid, fid: fid, verstr: "prod" );
close( soc );
if(egrep( pattern: "^([0-3]\\..*|4\\.([01](\\..*)?|2\\.(0(\\..*)?|1\\.([0-8]?[0-9]?" + "[0-9]|9[0-6][0-9]|97[0-6]))))$", string: cdBurnerXpVer )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

