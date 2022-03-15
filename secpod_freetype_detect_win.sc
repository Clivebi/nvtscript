if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901144" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "FreeType Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of FreeType.

The script logs in via smb, searches for FreeType in the registry and
gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
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
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\GnuWin32\\FreeType" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\GnuWin32\\FreeType" )){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "FreeType" )){
			ftVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(ftVer){
				appLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!appLoc){
					appLoc = "Couldn find the install location from registry";
				}
				set_kb_item( name: "FreeType/Win/Ver", value: ftVer );
				base = "cpe:/a:freetype:freetype:";
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "FreeType64/Win/Ver", value: ftVer );
					base = "cpe:/a:freetype:freetype:x64:";
				}
				register_and_report_cpe( app: appName, ver: ftVer, concluded: ftVer, base: base, expr: "^([0-9.]+)", insloc: appLoc );
			}
		}
	}
}

