if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808166" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-08 11:10:27 +0530 (Fri, 08 Jul 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Brackets Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detection of installed version
  of Adobe Brackets on Windows.

  The script logs in via smb, searches for Adobe Brackets in the registry
  and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( ContainsString( osArch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
for item in registry_enum_keys( key: key ) {
	brkName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( brkName, "Brackets" )){
		brkVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		brkPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!brkPath){
			brkPath = "Couldn find the install location from registry";
		}
		if(brkVer){
			set_kb_item( name: "AdobeBrackets/Win/Ver", value: brkVer );
			cpe = build_cpe( value: brkVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:brackets:" );
			if(!cpe){
				cpe = "cpe:/a:adobe:brackets";
			}
			register_product( cpe: cpe, location: brkPath );
			log_message( data: build_detection_report( app: "Adobe Brackets", version: brkVer, install: brkPath, cpe: cpe, concluded: brkVer ) );
			exit( 0 );
		}
	}
}

