if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814058" );
	script_version( "$Revision: 11698 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-29 05:57:28 +0200 (Sat, 29 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-09-28 14:56:21 +0530 (Fri, 28 Sep 2018)" );
	script_name( "Mercurial Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Mercurial.

  The script logs in via smb, searches registry for Mercurial and gets the version
  from 'DisplayVersion' string." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		merName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( merName, "Mercurial" )){
			merVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			merPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!merPath){
				merPath = "Unable to find the install location from registry";
			}
			set_kb_item( name: "Mercurial/Win/Installed", value: TRUE );
			register_and_report_cpe( app: "Mercurial", ver: merVer, base: "cpe:/a:mercurial:mercurial:", expr: "^([0-9.]+)", insloc: merPath );
			if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
				set_kb_item( name: "Mercurial64/Win/Ver", value: merVer );
				register_and_report_cpe( app: "Mercurial", ver: merVer, base: "cpe:/a:mercurial:mercurial:x64:", expr: "^([0-9.]+)", insloc: merPath );
			}
		}
	}
}
exit( 0 );

