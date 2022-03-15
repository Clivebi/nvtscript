if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900596" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "TFM MMPlayer Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the version of TFM MMPlayer." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "TFM MMPlayer Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
tfmKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MMPlayer_is1";
tfmName = registry_get_sz( key: tfmKey, item: "DisplayName" );
if(ContainsString( tfmName, "MMPlayer" )){
	tfmPath = registry_get_sz( key: tfmKey, item: "UninstallString" );
	tfmPath = ereg_replace( pattern: "\"(.*)\"", replace: "\\1", string: tfmPath );
	if(tfmPath != NULL){
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: tfmPath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: tfmPath - "\\unins000.exe" + "\\MMPlayer.exe" );
		mmplayerVer = GetVer( file: file, share: share );
		if(mmplayerVer != NULL){
			set_kb_item( name: "TFM/MMPlayer/Ver", value: mmplayerVer );
			log_message( data: "TFM MMPlayer version " + mmplayerVer + " was detected on the host" );
			cpe = build_cpe( value: mmplayerVer, exp: "^([0-9]\\.[0-9])", base: "cpe:/a:tfm:mmplayer:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

