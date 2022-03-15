if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800331" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Windows Live Messenger Client Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Windows Live Messenger.

  The script logs in via smb, searches for Microsoft Windows Live Messenger
  in the registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
checkduplicate = "";
checkduplicate_path = "";
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "Windows Live Messenger" )){
			livemgrVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			appLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!appLoc){
				appLoc = "Couldn find the install location from registry";
			}
			if(livemgrVer){
				if(ContainsString( checkduplicate, livemgrVer + ", " ) && ContainsString( checkduplicate_path, appLoc + ", " )){
					continue;
				}
				checkduplicate += livemgrVer + ", ";
				checkduplicate_path += appLoc + ", ";
				set_kb_item( name: "MS/LiveMessenger/Installed", value: TRUE );
				if( ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "MS/LiveMessenger64/Ver", value: livemgrVer );
					register_and_report_cpe( app: appName, ver: livemgrVer, base: "cpe:/a:microsoft:windows_live_messenger:x64:", expr: "^([0-9.]+)", insloc: appLoc );
				}
				else {
					set_kb_item( name: "MS/LiveMessenger/Ver", value: livemgrVer );
					register_and_report_cpe( app: appName, ver: livemgrVer, base: "cpe:/a:microsoft:windows_live_messenger:", expr: "^([0-9.]+)", insloc: appLoc );
				}
			}
		}
		if(ContainsString( appName, "Messenger Plus!" )){
			msgPlusVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			plusPath = registry_get_sz( key: key + item, item: "UninstallString" );
			plusPath = eregmatch( pattern: "\"(.*)\"", string: plusPath );
			if(isnull( msgPlusVer ) && plusPath[1]){
				file = plusPath[1];
				if( ContainsString( file, "Uninstall.exe" ) ){
					file -= "Uninstall.exe";
					msgPlusVer = fetch_file_version( sysPath: file, file_name: "MPTools.exe" );
					if(!msgPlusVer){
						msgPlusVer = fetch_file_version( sysPath: file, file_name: "WinksViewer.exe" );
					}
				}
				else {
					if(ContainsString( file, "MsgPlus.exe" )){
						file -= "MsgPlus.exe";
						msgPlusVer = fetch_file_version( sysPath: file, file_name: "MsgPlus.exe" );
					}
				}
			}
			if(!isnull( msgPlusVer )){
				set_kb_item( name: "MS/MessengerPlus/Path", value: plusPath[1] );
				set_kb_item( name: "MS/MessengerPlus/Installed", value: TRUE );
				if( ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "MS/MessengerPlus64/Ver", value: msgPlusVer );
					register_and_report_cpe( app: appName, ver: msgPlusVer, base: "cpe:/a:microsoft:messenger_plus%21_live:x64:", expr: "^([0-9.]+)", insloc: plusPath[1] );
				}
				else {
					set_kb_item( name: "MS/MessengerPlus/Ver", value: msgPlusVer );
					register_and_report_cpe( app: appName, ver: msgPlusVer, base: "cpe:/a:microsoft:messenger_plus%21_live:", expr: "^([0-9.]+)", insloc: plusPath[1] );
				}
			}
		}
	}
}

