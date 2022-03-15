if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902170" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)" );
	script_name( "Iswitch WS-FTP Client Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Iswitch
  WS-FTP Client.

  The script logs in via smb, searches for Iswitch WS-FTP Client in the registry
  and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Ipswitch\\WS_FTP" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Ipswitch\\WS_FTP" )){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(( ContainsString( appName, "Ipswitch" ) ) || ( ContainsString( appName, "WS_FTP" ) )){
			appAdd = registry_get_sz( key: key + item, item: "DisplayIcon" );
			appLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if( ContainsString( appAdd, "ftppro" ) ){
				install = TRUE;
			}
			else {
				if( appLoc ){
					checkpro = fetch_file_version( sysPath: appLoc, file_name: "wsftppro.exe" );
					if(checkpro){
						install = TRUE;
					}
				}
				else {
					exit( 0 );
				}
			}
			if(install){
				ipsVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
				if(ipsVer){
					if(!appLoc){
						appLoc = "Couldn find the install location from registry";
					}
					set_kb_item( name: "Ipswitch/WS_FTP_Pro/Client/Ver", value: ipsVer );
					cpe = build_cpe( value: ipsVer, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:ws_ftp:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:ipswitch:ws_ftp";
					}
					if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
						set_kb_item( name: "Ipswitch/WS_FTP_Pro64/Client/Ver", value: ipsVer );
						cpe = build_cpe( value: ipsVer, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:ws_ftp:x64:" );
						if(isnull( cpe )){
							cpe = "cpe:/a:ipswitch:ws_ftp:x64";
						}
					}
					register_product( cpe: cpe, location: appLoc );
					log_message( data: build_detection_report( app: appName, version: ipsVer, install: appLoc, cpe: cpe, concluded: ipsVer ) );
				}
			}
		}
	}
}

