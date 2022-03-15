if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96005" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2010-12-01 10:53:45 +0100 (Wed, 01 Dec 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Last Username (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script detects if Last Login Username an Loginwarning is displayed." );
	exit( 0 );
}
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
OSVER = get_kb_item( "WMI/WMI_OSVER" );
if(!OSVER || ContainsString( "none", OSVER )){
	set_kb_item( name: "WMI/DontDisplayLastUserName", value: "error" );
	set_kb_item( name: "WMI/LegalNoticeCaption", value: "error" );
	set_kb_item( name: "WMI/LegalNoticeText", value: "error" );
	log_message( port: 0, proto: "IT-Grundschutz", data: NASLString( "No access to SMB host. Firewall is activated or there is not a Windows system." ) );
	exit( 0 );
}
handle = wmi_connect_reg( host: host, username: usrname, password: passwd );
if(!handle){
	security_message( "wmi_connect_reg: WMI Connect failed." );
	set_kb_item( name: "WMI/DontDisplayLastUserName", value: "error" );
	set_kb_item( name: "WMI/LegalNoticeCaption", value: "error" );
	set_kb_item( name: "WMI/LegalNoticeText", value: "error" );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
WINLOGONKEY = wmi_reg_enum_value( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" );
POLICIEKEY = wmi_reg_enum_value( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" );
if(!WINLOGONKEY){
	log_message( port: 0, proto: "IT-Grundschutz", data: "Registry Path not found." );
	set_kb_item( name: "WMI/DontDisplayLastUserName", value: "error" );
	set_kb_item( name: "WMI/LegalNoticeCaption", value: "error" );
	set_kb_item( name: "WMI/LegalNoticeText", value: "error" );
	exit( 0 );
}
lastuser = wmi_reg_get_dword_val( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", val_name: "DontDisplayLastUserName" );
lastuserpol = wmi_reg_get_dword_val( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", val_name: "DontDisplayLastUserName" );
lenoca = wmi_reg_get_sz( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", key_name: "LegalNoticeCaption" );
lenocapol = wmi_reg_get_sz( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", key_name: "LegalNoticeCaption" );
lenote = wmi_reg_get_sz( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", key_name: "LegalNoticeText" );
lenotepol = wmi_reg_get_sz( wmi_handle: handle, key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", key_name: "legalnoticetext" );
if(!POLICIEKEY){
	lastuserpol = 0;
	lenocapol = "";
	lenotepol = "";
}
if( ( lastuser == 1 ) || ( lastuserpol == 1 ) ){
	set_kb_item( name: "WMI/DontDisplayLastUserName", value: "on" );
}
else {
	if( ( lastuser != 1 ) && ( lastuserpol == 1 ) ){
		set_kb_item( name: "WMI/DontDisplayLastUserName", value: "on" );
	}
	else {
		set_kb_item( name: "WMI/DontDisplayLastUserName", value: "off" );
	}
}
if( ContainsString( "", lenoca ) && ContainsString( "", lenocapol ) ){
	set_kb_item( name: "WMI/LegalNoticeCaption", value: "off" );
}
else {
	set_kb_item( name: "WMI/LegalNoticeCaption", value: "on" );
}
if( ContainsString( "", lenote ) && ContainsString( "", lenotepol ) ){
	set_kb_item( name: "WMI/LegalNoticeText", value: "off" );
}
else {
	set_kb_item( name: "WMI/LegalNoticeText", value: "on" );
}
wmi_close( wmi_handle: handle );
exit( 0 );

