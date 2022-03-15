if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809817" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-11-23 16:58:28 +0530 (Wed, 23 Nov 2016)" );
	script_name( "Git Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Git.

  The script logs in via smb, searches for 'Git Version' in the registry,
  gets version and installation path information from the registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		gitName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( gitName, "Git version" )){
			gitVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			gitPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!gitPath){
				gitPath = "Unable to find the install location from registry";
			}
			set_kb_item( name: "Git/Win/Ver", value: gitVer );
			cpe = build_cpe( value: gitVer, exp: "^([0-9.]+)", base: "cpe:/a:git_for_windows_project:git_for_windows:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:git_for_windows_project:git_for_windows";
			}
			if(ContainsString( os_arch, "64" )){
				set_kb_item( name: "Git/x64/Win/Ver", value: gitVer );
				cpe = build_cpe( value: gitVer, exp: "^([0-9.]+)", base: "cpe:/a:git_for_windows_project:git_for_windows:x64:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:git_for_windows_project:git_for_windows:x64";
				}
			}
			register_product( cpe: cpe, location: gitPath );
			log_message( data: build_detection_report( app: gitName, version: gitVer, install: gitPath, cpe: cpe, concluded: gitVer ) );
		}
	}
}

