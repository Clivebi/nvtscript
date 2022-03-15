if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806979" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2016-01-20 15:17:03 +0530 (Wed, 20 Jan 2016)" );
	script_name( "McAfee Application Control Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  McAfee Application Control.

  The script detects the version of McAfee Application Control." );
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
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(isnull( key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	mcafeeName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( mcafeeName, "McAfee Solidifier" )){
		mcafeeVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!mcafeeVer){
			mcafeeVer = "Unknown";
		}
		mcafeePath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!mcafeePath){
			mcafeePath = "Unable to find the install location from registry";
		}
		set_kb_item( name: "McAfee/Application/Control/Win/Installed", value: TRUE );
		if( ContainsString( os_arch, "64" ) ){
			set_kb_item( name: "McAfee/Application/Control64/Win/Ver", value: mcafeeVer );
			register_and_report_cpe( app: "McAfee Application Control", ver: mcafeeVer, base: "cpe:/a:mcafee:application_control:x64:", expr: "^([0-9.]+)", insloc: mcafeePath );
		}
		else {
			set_kb_item( name: "McAfee/Application/Control/Win/Ver", value: mcafeeVer );
			register_and_report_cpe( app: "McAfee Application Control", ver: mcafeeVer, base: "cpe:/a:mcafee:application_control:", expr: "^([0-9.]+)", insloc: mcafeePath );
		}
		exit( 0 );
	}
}

