if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900528" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VLC Media Player Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of VLC Media Player version on Windows.

The script logs in via smb, searches for VLC Media Player in the registry
and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\VideoLAN\\VLC" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\VideoLAN\\VLC",
			 "SOFTWARE\\Wow6432Node\\VideoLAN\\VLC" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\VideoLAN\\VLC" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\VideoLAN\\VLC" )){
		exit( 0 );
	}
}
for key in key_list {
	vlcVer = registry_get_sz( item: "Version", key: key );
	vlcPath = registry_get_sz( item: "InstallDir", key: key );
	if(vlcVer != NULL && vlcPath != NULL){
		set_kb_item( name: "VLCPlayer/Win/Installed", value: TRUE );
		set_kb_item( name: "VLCPlayer/Win/Ver", value: vlcVer );
		register_and_report_cpe( app: "VLC Media Player", ver: vlcVer, base: "cpe:/a:videolan:vlc_media_player:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: vlcPath );
		if(ContainsString( os_arch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
			set_kb_item( name: "VLCPlayer64/Win/Ver", value: vlcVer );
			register_and_report_cpe( app: "VLC Media Player", ver: vlcVer, base: "cpe:/a:videolan:vlc_media_player:x64:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: vlcPath );
		}
	}
}

