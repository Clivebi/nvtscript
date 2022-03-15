if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900947" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)" );
	script_name( "Gabset Media Player Classic Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Gabset Media Player
  Classic.

  The script logs in via smb, searches for Media Player Classic in the registry,
  gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
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
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Gabest\\Media Player Classic\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Gabest\\Media Player Classic\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	mpcPath = registry_get_sz( key: key, item: "ExePath" );
	if(mpcPath){
		cpath_list = split( buffer: mpcPath, sep: "\\", keep: FALSE );
		exeName = cpath_list[max_index( cpath_list ) - 1];
		mpcVer = fetch_file_version( sysPath: mpcPath - exeName, file_name: exeName );
		mpcPath = mpcPath - exeName;
		if(!mpcVer){
			mpcVer = "unknown";
		}
		if(mpcVer){
			set_kb_item( name: "MediaPlayerClassic/Ver", value: mpcVer );
			cpe = build_cpe( value: mpcVer, exp: "^([0-9.]+)", base: "cpe:/a:rob_schultz:media_player_classic:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:rob_schultz:media_player_classic";
			}
			register_product( cpe: cpe, location: mpcPath );
			log_message( data: build_detection_report( app: "Gabest Media Player Classic", version: mpcVer, install: mpcPath, cpe: cpe, concluded: mpcVer ) );
		}
	}
}

