if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902915" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-05-30 14:53:42 +0530 (Wed, 30 May 2012)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft MSN Messenger Service Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft MSN Messenger.

The script logs in via smb, searches for Microsoft MSN Messenger in the
registry and gets the exe file path from 'InstallationDirectory' string
in registry and version from the 'msmsgs.exe'" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\MessengerService" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\MessengerService" )){
		exit( 0 );
	}
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\MessengerService\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\SOFTWARE\\Microsoft\\MessengerService\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	path = registry_get_sz( key: key, item: "InstallationDirectory" );
	if( path ){
		msnVer = fetch_file_version( sysPath: path, file_name: "msmsgs.exe" );
	}
	else {
		if( !ContainsString( key, "Wow6432Node" ) ){
			msgKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
		}
		else {
			msgKey = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
		}
		for item in registry_enum_keys( key: msgKey ) {
			apName = registry_get_sz( key: msgKey + item, item: "DisplayName" );
			if(ContainsString( apName, "MSN Messenger" )){
				msnVer = registry_get_sz( key: msgKey + item, item: "DisplayVersion" );
				path = "Unable to get install Path";
			}
		}
	}
	if(msnVer){
		set_kb_item( name: "Microsoft/MSN/Messenger/Ver", value: msnVer );
		register_and_report_cpe( app: "Microsoft MSN Messenger Service", ver: msnVer, base: "cpe:/a:microsoft:msn_messenger:", expr: "^([0-9.]+)", insloc: path );
		exit( 0 );
	}
}

