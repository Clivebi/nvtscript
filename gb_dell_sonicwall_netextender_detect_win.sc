if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806042" );
	script_version( "2020-08-04T09:17:36+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-04 09:17:36 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-09-08 13:38:49 +0530 (Tue, 08 Sep 2015)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Dell SonicWall NetExtender Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Dell SonicWall NetExtender on Windows.

  The script logs in via smb, searches for 'Dell SonicWall NetExtender' in the
  registry and gets the version from 'DisplayVersion' string from
  registry." );
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
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(isnull( key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	netextName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( netextName, "Dell SonicWALL NetExtender" )){
		netextVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		netextPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!netextPath){
			netextPath = "Unable to find the install location from registry";
		}
		if(netextVer){
			set_kb_item( name: "Dell/SonicWall/NetExtender/Win/Ver", value: netextVer );
			register_and_report_cpe( app: "Dell SonicWall NetExtender", ver: netextVer, base: "cpe:/a:sonicwall:netextender:", expr: "^([0-9.]+)", insloc: netextPath );
		}
	}
}

