if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801356" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)" );
	script_name( "HP StorageWorks Storage Mirroring Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of HP StorageWorks Storage Mirroring on Windows.

  The script logs in via smb, searches for HP Storage Mirroring in the
  registry and gets the version." );
	script_tag( name: "qod_type", value: "registry" );
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
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		hpsmName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( hpsmName, "HP Storage Mirroring" )){
			hpsmVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(hpsmVer != NULL){
				insLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insLoc){
					insLoc = "Could not find the install location from registry";
				}
				set_kb_item( name: "HP/SWSM/Installed", value: TRUE );
				if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "HP/SWSM64/Ver", value: hpsmVer );
					register_and_report_cpe( app: hpsmName, ver: hpsmVer, concluded: hpsmVer, base: "cpe:/a:hp:storageworks_storage_mirroring:x64:", expr: "^([0-9.]+)", insloc: insLoc );
				}
				else {
					set_kb_item( name: "HP/SWSM/Ver", value: hpsmVer );
					register_and_report_cpe( app: hpsmName, ver: hpsmVer, concluded: hpsmVer, base: "cpe:/a:hp:storageworks_storage_mirroring:", expr: "^([0-9.]+)", insloc: insLoc );
				}
			}
		}
	}
}

