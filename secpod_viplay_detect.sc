if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900360" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "URUWorks ViPlay Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script is detects the installed version of ViPlay Media
  Player." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "URUWorks ViPlay Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
viplayKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: viplayKey )){
	exit( 0 );
}
for item in registry_enum_keys( key: viplayKey ) {
	viplayName = registry_get_sz( key: viplayKey + item, item: "DisplayName" );
	if(ContainsString( viplayName, "URUSoft ViPlay" )){
		viplayPath = registry_get_sz( key: viplayKey + item, item: "UninstallString" );
		viplayPath = ereg_replace( pattern: "\"", string: viplayPath, replace: "" );
	}
	if(viplayPath != NULL){
		for viplay in make_list( "ViPlay.exe",
			 "ViPlay3.exe",
			 "ViPlay4.exe" ) {
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: viplayPath );
			file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: viplayPath - "uninstall.exe" + viplay );
			viplayVer = GetVer( file: file, share: share );
			if(viplayVer != NULL){
				set_kb_item( name: "ViPlay/MediaPlayer/Ver", value: viplayVer );
				log_message( data: "ViPlay Media Player version " + viplayVer + " was detected on the host" );
				cpe = build_cpe( value: viplayVer, exp: "^([0-9.]+)", base: "cpe:/a:urusoft:viplay3:" );
				if(!isnull( cpe )){
					register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
				}
			}
		}
	}
}

