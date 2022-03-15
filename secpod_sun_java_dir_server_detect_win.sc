if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900492" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Sun Java Directory Server Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of Sun Java Directory Server.

  This script detects the version of Directory Server." );
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
	key = "SOFTWARE\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\";
	}
}
key1 = key + "Sun Microsystems\\DirectoryServer\\";
key2 = key + "Microsoft\\Windows\\CurrentVersion\\Uninstall\\Directory Server\\";
if( registry_key_exists( key: key1 ) ){
	for item in registry_enum_keys( key: key1 ) {
		ver = eregmatch( pattern: "([0-9]\\.[0-9.]+)", string: item );
		if(!isnull( ver[1] )){
			set_kb_item( name: "Sun/JavaDirServer/Win/Ver", value: ver[1] );
			path = "Not able to find the install Location";
			register_and_report_cpe( app: "Sun Java Directory Server", ver: ver[1], concluded: ver[1], base: "cpe:/a:sun:java_system_directory_server:", expr: "^([0-9.]+)", insloc: path );
		}
	}
}
else {
	if(registry_key_exists( key: key2 )){
		appregCheck = registry_get_sz( key: key2, item: "DisplayName" );
		if(ContainsString( appregCheck, "Directory Server" )){
			infPath = registry_get_sz( key: key2, item: "UninstallString" );
			infPath = ereg_replace( pattern: "\"", string: infPath, replace: "" );
			infFile = infPath - "uninstall_dirserver.exe" + "setup\\slapd\\slapd.inf";
			infContent = smb_read_file( fullpath: infFile, offset: 0, count: 256 );
			if(ContainsString( infContent, "Directory Server" )){
				appVer = eregmatch( pattern: "System Directory Server ([0-9]\\.[0-9.]+)", string: infContent );
				if(!isnull( appVer[1] )){
					set_kb_item( name: "Sun/JavaDirServer/Win/Ver", value: appVer[1] );
					register_and_report_cpe( app: appregCheck, ver: appVer[1], concluded: appVer[1], base: "cpe:/a:sun:java_system_directory_server:", expr: "^([0-9.]+)", insloc: infPath );
				}
			}
		}
	}
}
exit( 0 );

