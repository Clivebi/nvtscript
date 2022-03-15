if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802980" );
	script_version( "$Revision: 10902 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-10 10:36:03 +0530 (Wed, 10 Oct 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft FAST Search Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft FAST Search Server.

The script logs in via smb, searches for Microsoft FAST Search Server in the
registry and gets the version from 'Version' string in registry" );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
fsKey = "SOFTWARE\\Microsoft\\FAST Search Server";
if(!registry_key_exists( key: fsKey )){
	exit( 0 );
}
fsKey = fsKey + "\\Setup";
insPath = registry_get_sz( key: fsKey, item: "Path" );
if(!insPath){
	insPath = "Could not find the install location from registry";
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	fsName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(!fsName){
		continue;
	}
	if(ContainsString( fsName, "Microsoft FAST Search Server" )){
		ver = eregmatch( string: fsName, pattern: "([0-9]+)" );
		fsVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(fsVer){
			set_kb_item( name: "MS/SharePoint/Server/Ver", value: fsVer );
			set_kb_item( name: "MS/SharePoint/Install/Path", value: insPath );
			if( ver[0] ){
				cpe = build_cpe( value: fsVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:fast_search_server_for_sharepoint:" + ver[0] );
			}
			else {
				cpe = build_cpe( value: fsVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:fast_search_server_for_sharepoint:" );
			}
			if(!cpe){
				cpe = "cpe:/a:microsoft:fast_search_server_for_sharepoint";
			}
			register_product( cpe: cpe, location: insPath );
			log_message( data: build_detection_report( app: "MS Fast Search Server version", version: fsVer, install: insPath, cpe: cpe, concluded: fsVer ) );
			exit( 0 );
		}
	}
}

