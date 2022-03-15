if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96033" );
	script_version( "2021-09-03T12:03:56+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 12:03:56 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Read the Windows Password Policy over WMI (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_tag( name: "summary", value: "This script reads the Windows Password Policy configuration over WMI." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("wmi_rsop.inc.sc");
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
passwd = kb_smb_password();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
OSVER = get_kb_item( "WMI/WMI_OSVER" );
WindowsDomainrole = get_kb_item( "WMI/WMI_WindowsDomainrole" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/lockoutpolicy", value: "error" );
	set_kb_item( name: "WMI/passwdpolicy", value: "error" );
	set_kb_item( name: "WMI/passwdpolicy/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handle = wmi_connect( host: host, username: usrname, password: passwd, ns: "root\\rsop\\computer" );
if(!handle){
	set_kb_item( name: "WMI/lockoutpolicy", value: "error" );
	set_kb_item( name: "WMI/passwdpolicy", value: "error" );
	set_kb_item( name: "WMI/passwdpolicy/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
pwdList = wmi_rsop_passwdpolicy( handle );
if( pwdList != NULL ){
	pwdList = split( buffer: pwdList, sep:"\\n", keep: 0 );
	for(i = 1;i < max_index( pwdList );i++){
		desc = split( buffer: pwdList[i], sep: "|", keep: 0 );
		if(desc != NULL){
			set_kb_item( name: "WMI/passwdpolicy/" + desc[4], value: desc[7] );
		}
	}
}
else {
	set_kb_item( name: "WMI/passwdpolicy", value: "False" );
}
lkList = wmi_rsop_lockoutpolicy( handle );
if( lkList != NULL ){
	lkList = split( buffer: lkList, sep:"\\n", keep: 0 );
	for(i = 1;i < max_index( lkList );i++){
		desc = split( buffer: lkList[i], sep: "|", keep: 0 );
		if(desc != NULL){
			set_kb_item( name: "WMI/lockoutpolicy/" + desc[4], value: desc[7] );
		}
	}
}
else {
	set_kb_item( name: "WMI/lockoutpolicy", value: "False" );
}
if(OSVER >= "6.2"){
	pinLogin = registry_get_dword( key: "SOFTWARE\\Microsoft\\PolicyManager\\default\\Settings\\AllowSignInOptions", item: "value", type: "HKLM" );
	if( pinLogin || pinLogin == "0" ){
		set_kb_item( name: "WMI/passwdpolicy/pinLogin", value: pinLogin );
	}
	else {
		set_kb_item( name: "WMI/passwdpolicy/pinLogin", value: "None" );
	}
}
wmi_close( wmi_handle: handle );
set_kb_item( name: "WMI/lockoutpolicy/stat", value: "ok" );
set_kb_item( name: "WMI/passwdpolicy/stat", value: "ok" );
exit( 0 );

