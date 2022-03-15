if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817317" );
	script_version( "2020-07-30T05:44:36+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-30 05:44:36 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-27 11:50:35 +0530 (Mon, 27 Jul 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft OneDrive Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Microsoft OneDrive.

  The script logs in via smb, searches for Microsoft OneDrive in the
  registry and gets the version from 'DisplayVersion' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
key = "SOFTWARE\\Microsoft\\OneDrive";
if(!registry_key_exists( key: key, type: "HKCU" )){
	exit( 0 );
}
appName = registry_get_sz( key: key, item: "CurrentVersionPath", type: "HKCU" );
if(IsMatchRegexp( appName, "Microsoft.OneDrive" )){
	appPath = eregmatch( pattern: "(.*OneDrive)", string: appName );
	if( !appPath ){
		appPath = "Couldn find the install location from registry";
	}
	else {
		appPath = appPath[0];
	}
	version = registry_get_sz( key: key, item: "Version", type: "HKCU" );
	if(!version){
		version = "Unknown";
	}
	set_kb_item( name: "microsoft/onedrive/win/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:onedrive:" );
	if(!cpe){
		cpe = "cpe:/a:microsoft:onedrive";
	}
	if(ContainsString( os_arch, "x64" )){
		set_kb_item( name: "microsoft/onedrive/x64/win", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:onedrive:x64:" );
		if(!cpe){
			cpe = "cpe:/a:adobe:premiere_pro:x64";
		}
	}
	register_and_report_cpe( app: "Microsoft OneDrive", ver: version, concluded: "Microsoft OneDrive", cpename: cpe, insloc: appPath );
	exit( 0 );
}
exit( 0 );

