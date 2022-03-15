if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800947" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "CuteFTP Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of CuteFTP on Windows.

The script logs in via smb, searches for CuteFTP in the registry
and gets the install location and extract version from the file." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
appKey_list = make_list( "SOFTWARE\\GlobalSCAPE",
	 "SOFTWARE\\GlobalSCAPE Inc.",
	 "SOFTWARE\\Wow6432Node\\GlobalSCAPE",
	 "SOFTWARE\\Wow6432Node\\GlobalSCAPE Inc." );
for appKey in appKey_list {
	if(registry_key_exists( key: appKey )){
		appExists = TRUE;
		break;
	}
}
if(!appExists){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		cName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( cName, "CuteFTP" )){
			cftpName = eregmatch( pattern: "CuteFTP [0-9.?]+ ([a-zA-Z]+)", string: cName );
			cPath = registry_get_sz( key: key + item, item: "DisplayIcon" );
			if(cPath == NULL){
				exit( 0 );
			}
			cPath = cPath - ",-0";
			cpath_list = split( buffer: cPath, sep: "\\", keep: 0 );
			exeName = cpath_list[max_index( cpath_list ) - 1];
			cftpVer = fetch_file_version( sysPath: cPath - exeName, file_name: exeName );
			if(cftpVer){
				if(cftpName[1]){
					set_kb_item( name: "CuteFTP/" + NASLString( cftpName[1] ) + "/Ver", value: cftpVer );
				}
				set_kb_item( name: "CuteFTP/Win/Ver", value: cftpVer );
				cpe = build_cpe( value: cftpVer, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:globalscape:cuteftp:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:globalscape:cuteftp";
				}
				register_product( cpe: cpe, location: cPath );
				log_message( data: build_detection_report( app: cName, version: cftpVer, install: cPath, cpe: cpe, concluded: cftpVer ) );
			}
		}
	}
}

