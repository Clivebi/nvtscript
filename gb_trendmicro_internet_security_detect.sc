if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801263" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Trend Micro Internet Security Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Trend Micro Internet Security on Windows.

The script logs in via smb, searches for Trend Micro Internet Security in the
registry and gets the version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\TrendMicro\\" )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	AppName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( AppName, "Trend Micro" ) && ContainsString( AppName, "Internet Security" )){
		AppVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(AppVer != NULL){
			insLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insLoc){
				insLoc = "Could not find the install location from registry";
			}
			set_kb_item( name: "TrendMicro/IS/Installed", value: TRUE );
			if( ContainsString( os_arch, "64" ) ){
				set_kb_item( name: "TrendMicro/IS64/Ver", value: AppVer );
				register_and_report_cpe( app: AppName, ver: AppVer, concluded: AppName, base: "cpe:/a:trendmicro:internet_security:x64:", expr: "^([0-9.]+)", insloc: insLoc );
			}
			else {
				set_kb_item( name: "TrendMicro/IS/Ver", value: AppVer );
				register_and_report_cpe( app: AppName, ver: AppVer, concluded: AppName, base: "cpe:/a:trendmicro:internet_security:", expr: "^([0-9.]+)", insloc: insLoc );
			}
		}
	}
}

