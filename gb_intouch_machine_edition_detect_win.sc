if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812216" );
	script_version( "$Revision: 11420 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2017-11-20 14:22:07 +0530 (Mon, 20 Nov 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "InTouch Machine Edition Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  InTouch Machine Edition.

  The script logs in via smb, searches for InTouch Machine Edition in the
  registry and gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		itmName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( itmName, "InTouch Machine Edition" )){
			itmVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			itmPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!itmPath){
				itmPath = "Unable to find the install location from registry";
			}
			if(itmVer){
				set_kb_item( name: "InTouch/MachineEdition/Win/Ver", value: itmVer );
				register_and_report_cpe( app: "InTouch Machine Edition", ver: itmVer, base: "cpe:/a:schneider_electric:intouch_machine_edition:", expr: "^([0-9.]+)", insloc: itmPath );
			}
		}
	}
}

