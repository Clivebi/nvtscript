if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813331" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-05-08 13:30:09 +0530 (Tue, 08 May 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Trend Micro Maximum Security Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detection of installed version
  of Trend Micro Maximum Security on Windows.

  The script logs in via smb, searches for Trend Micro Maximum Security in the
  registry and gets the version from registry." );
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
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\TrendMicro\\" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	AppName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( AppName, "Trend Micro Maximum Security" )){
		AppVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(AppVer != NULL){
			insLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insLoc){
				insLoc = "Could not find the install location from registry";
			}
			set_kb_item( name: "TrendMicro/MS/Installed", value: TRUE );
			set_kb_item( name: "TrendMicro/MS/Ver", value: AppVer );
			register_and_report_cpe( app: AppName, ver: AppVer, base: "cpe:/a:trendmicro:maximum_security:", expr: "^([0-9.]+)", insloc: insLoc );
			if(ContainsString( osArch, "64" )){
				set_kb_item( name: "TrendMicro/MS64/Ver", value: AppVer );
				register_and_report_cpe( app: AppName, ver: AppVer, base: "cpe:/a:trendmicro:maximum_security:x64:", expr: "^([0-9.]+)", insloc: insLoc );
			}
		}
	}
}
exit( 0 );

