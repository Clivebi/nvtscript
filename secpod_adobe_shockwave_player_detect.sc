if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900581" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)" );
	script_name( "Adobe Shockwave Player Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe
  Shockwave Player on Windows.

  The script logs in via smb, searches for Adobe Shockwave Player in the
  registry, gets the version." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Adobe" )){
	if(!registry_key_exists( key: "SOFTWARE\\Macromedia" )){
		if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Adobe" )){
			if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Macromedia" )){
				exit( 0 );
			}
		}
	}
}
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
for item in registry_enum_keys( key: key ) {
	swplayerName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( swplayerName, "Shockwave" )){
		unintPath = registry_get_sz( key: key + item, item: "UninstallString" );
		break;
	}
}
if(unintPath != NULL){
	swPath = smb_get_systemroot();
	if(swPath == NULL){
		exit( 0 );
	}
	if( ContainsString( unintPath, "Adobe" ) ){
		path = "Adobe";
	}
	else {
		if(ContainsString( unintPath, "Macromed" )){
			path = "Macromed";
		}
	}
	if( ContainsString( os_arch, "x64" ) ){
		sys = "\\SysWOW64\\";
	}
	else {
		if(ContainsString( os_arch, "x86" )){
			sys = "\\System32\\";
		}
	}
	exePath = swPath + sys + path + "\\Shockwave";
	swVer = fetch_file_version( sysPath: exePath, file_name: "swinit.exe" );
	if(!swVer){
		for(i = 8;i <= 12;i++){
			swVer = fetch_file_version( sysPath: exePath + " " + i, file_name: "swinit.exe" );
			if(swVer != NULL){
				exePath = exePath + " " + i;
				break;
			}
		}
	}
	if(swVer){
		set_kb_item( name: "Adobe/ShockwavePlayer/Ver", value: swVer );
		cpe = build_cpe( value: swVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:shockwave_player:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:adobe:shockwave_player";
		}
		register_product( cpe: cpe, location: exePath );
		log_message( data: build_detection_report( app: swplayerName, version: swVer, install: exePath, cpe: cpe, concluded: swVer ) );
	}
}

