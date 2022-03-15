if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96058" );
	script_version( "$Revision: 10949 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Get Screensaver Status for ALL Users (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB", "Tools/Present/wmi" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "The script detects if Screensaver is activated and secured." );
	exit( 0 );
}
require("wmi_user.inc.sc");
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
	set_kb_item( name: "WMI/Screensaver", value: "error" );
	set_kb_item( name: "WMI/Screensaver/log", value: "No access to SMB host.\\nFirewall is activated or there is not a Windows system." );
	exit( 0 );
}
handlereg = wmi_connect_reg( host: host, username: usrname, password: passwd );
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handlereg){
	set_kb_item( name: "WMI/Screensaver", value: "error" );
	set_kb_item( name: "WMI/Screensaver/log", value: "wmi_connect: WMI Connect failed." );
	wmi_close( wmi_handle: handlereg );
	wmi_close( wmi_handle: handle );
	exit( 0 );
}
sysLst = wmi_user_sysaccount( handle );
usrLst = wmi_user_useraccount( handle );
Lst = sysLst + usrLst;
Lst = split( buffer: Lst, sep:"\\n", keep: 0 );
for(i = 1;i < max_index( Lst );i++){
	if(ContainsString( Lst[i], "Domain|Name|SID" )){
		continue;
	}
	desc = split( buffer: Lst[i], sep: "|", keep: 0 );
	if(desc != NULL){
		SID = desc[2];
		if(SID == "S-1-5-18" || SID == "S-1-5-19" || SID == "S-1-5-20"){
			continue;
		}
		testval = wmi_reg_enum_value( key: SID + "\\\\Control Panel\\\\Desktop", hive: 0x80000003, wmi_handle: handlereg );
		if(testval){
			screenkey = SID + "\\\\Control Panel\\\\Desktop";
			domscreenkey = SID + "\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Control Panel\\\\Desktop";
			ScreenSaveActive = wmi_reg_get_sz( wmi_handle: handlereg, hive: 0x80000003, key: screenkey, key_name: "ScreenSaveActive" );
			ScreenSaverIsSecure = wmi_reg_get_sz( wmi_handle: handlereg, hive: 0x80000003, key: screenkey, key_name: "ScreenSaverIsSecure" );
			ScreenSaveTimeOut = wmi_reg_get_sz( wmi_handle: handlereg, hive: 0x80000003, key: screenkey, key_name: "ScreenSaveTimeOut" );
			DomScreenSaveActive = wmi_reg_get_sz( wmi_handle: handlereg, hive: 0x80000003, key: domscreenkey, key_name: "ScreenSaveActive" );
			DomScreenSaverIsSecure = wmi_reg_get_sz( wmi_handle: handlereg, hive: 0x80000003, key: domscreenkey, key_name: "ScreenSaverIsSecure" );
			DomScreenSaveTimeOut = wmi_reg_get_sz( wmi_handle: handlereg, hive: 0x80000003, key: domscreenkey, key_name: "ScreenSaveTimeOut" );
			if(!ScreenSaveActive){
				ScreenSaveActive = "none";
			}
			if(!DomScreenSaveActive){
				DomScreenSaveActive = "none";
			}
			if(!ScreenSaverIsSecure){
				ScreenSaverIsSecure = "none";
			}
			if(!DomScreenSaverIsSecure){
				DomScreenSaverIsSecure = "none";
			}
			if(!ScreenSaveTimeOut){
				ScreenSaveTimeOut = "none";
			}
			if(!DomScreenSaveTimeOut){
				DomScreenSaveTimeOut = "none";
			}
			value += desc[0] + "\\" + desc[1] + ";ScreenSaveActive=" + ScreenSaveActive + ";ScreenSaverIsSecure=" + ScreenSaverIsSecure + ";ScreenSaveTimeOut=" + ScreenSaveTimeOut + ";DomScreenSaveActive=" + DomScreenSaveActive + ";DomScreenSaverIsSecure=" + DomScreenSaverIsSecure + ";DomScreenSaveTimeOut=" + DomScreenSaveTimeOut + "\n";
		}
	}
}
if(!value){
	value = "none";
}
set_kb_item( name: "WMI/Screensaver", value: value );
wmi_close( wmi_handle: handlereg );
wmi_close( wmi_handle: handle );
exit( 0 );

