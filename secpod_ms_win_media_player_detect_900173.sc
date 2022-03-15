if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900173" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Windows Media Player Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Windows Media Player.

The script logs in via smb, searches for Windows Media Player CLSID
in the registry, gets version and set it in the KB item." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
key_list = make_list( "SOFTWARE\\Microsoft\\Active setup\\Installed Components\\" );
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	wmpVer = registry_get_sz( key: key + "{6BF52A52-394A-11d3-B153-00C04F79FAA6}", item: "Version" );
	if(!wmpVer){
		wmpVer = registry_get_sz( key: key + "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}", item: "Version" );
	}
	if(!wmpVer){
		exit( 0 );
	}
	wmpVer = ereg_replace( string: wmpVer, pattern: ",", replace: "." );
	pathKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wmplayer.exe";
	if(registry_key_exists( key: pathKey )){
		insloc = registry_get_sz( key: pathKey, item: "Path" );
		insloc = ereg_replace( string: insloc, pattern: "%", replace: "" );
	}
	if(!insloc){
		insloc = "Could not find the install location from registry";
	}
	set_kb_item( name: "Win/MediaPlayer/Ver", value: wmpVer );
	cpe = build_cpe( value: wmpVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:windows_media_player:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:microsoft:windows_media_player";
	}
	if(ContainsString( os_arch, "x64" ) && !ContainsString( insloc, "x86" )){
		set_kb_item( name: "Win/MediaPlayer64/Ver", value: wmpVer );
		cpe = build_cpe( value: wmpVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:windows_media_player:x64:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:microsoft:windows_media_player:x64";
		}
	}
	register_product( cpe: cpe, location: insloc );
	log_message( data: build_detection_report( app: "Microsoft Windows Media Player", version: wmpVer, install: insloc, cpe: cpe, concluded: wmpVer ) );
}

