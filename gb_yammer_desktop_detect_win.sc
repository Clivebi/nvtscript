if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814323" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-11-22 11:16:44 +0530 (Thu, 22 Nov 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Yammer Desktop Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Yammer Desktop
  on Windows.

  The script logs in via smb, searches for Telegram Desktop and gets the
  version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
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
if( ContainsString( osArch, "x64" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x86" )){
		key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(!registry_key_exists( key: key, type: "HKCU" )){
	exit( 0 );
}
for item in registry_enum_keys( key: key, type: "HKCU" ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName", type: "HKCU" );
	if(ContainsString( appName, "Yammer" )){
		yamPath = registry_get_sz( key: key + item, item: "InstallLocation", type: "HKCU" );
		yamVer = registry_get_sz( key: key + item, item: "DisplayVersion", type: "HKCU" );
		if(!yamVer){
			exit( 0 );
		}
		set_kb_item( name: "Microsoft/Yammer/Win/Ver", value: yamVer );
		cpe = build_cpe( value: yamVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:yammer:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:microsoft:yammer";
		}
		register_product( cpe: cpe, location: yamPath, service: "smb-login", port: 0 );
		report = build_detection_report( app: "Yammer", version: yamVer, install: yamPath, cpe: cpe, concluded: yamVer );
		if(report){
			log_message( port: 0, data: report );
		}
	}
}
exit( 0 );

