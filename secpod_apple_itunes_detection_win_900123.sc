if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900123" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)" );
	script_name( "Apple iTunes Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Apple iTunes on Windows.

  The script logs in via smb, searches for Apple iTunes in the registry
  and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
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
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	ituneName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(IsMatchRegexp( ituneName, "^(iTunes)$" )){
		insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!insPath){
			insPath = "Could not find the install Location from registry";
		}
		ituneVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(ituneVer){
			set_kb_item( name: "iTunes/Win/Installed", value: TRUE );
			set_kb_item( name: "iTunes/Win/Ver", value: ituneVer );
			register_and_report_cpe( app: ituneName, ver: ituneVer, base: "cpe:/a:apple:itunes:", expr: "^([0-9.]+)", insloc: insPath );
			if(ContainsString( os_arch, "64" )){
				set_kb_item( name: "iTunes/Win64/Ver", value: ituneVer );
				register_and_report_cpe( app: ituneName, ver: ituneVer, base: "cpe:/a:apple:itunes:x64:", expr: "^([0-9.]+)", insloc: insPath );
			}
		}
		exit( 0 );
	}
}

