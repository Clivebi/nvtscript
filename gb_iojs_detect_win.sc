if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805942" );
	script_version( "$Revision: 10915 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-04 17:21:51 +0530 (Tue, 04 Aug 2015)" );
	script_name( "io.js Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  io.js.

  The script logs in via smb, searches for 'io.js'in the registry and gets
  the version from 'DisplayVersion' string from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "io.js" )){
			ioVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			ioPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!ioPath){
				ioPath = "Unable to find the install location from registry";
			}
			set_kb_item( name: "iojs/Win/Installed", value: TRUE );
			if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
				set_kb_item( name: "iojs64/Win/Ver", value: ioVer );
				register_and_report_cpe( app: "io.js", ver: ioVer, base: "cpe:/a:iojs:io.js:x64:", expr: "^([0-9.]+)", insloc: ioPath );
			}
			else {
				set_kb_item( name: "iojs/Win/Ver", value: ioVer );
				register_and_report_cpe( app: "io.js", ver: ioVer, base: "cpe:/a:iojs:io.js:", expr: "^([0-9.]+)", insloc: ioPath );
			}
		}
	}
}

