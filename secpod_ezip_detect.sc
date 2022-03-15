if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900524" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-24 05:22:25 +0100 (Tue, 24 Mar 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "eZip Wizard Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of eZip Wizard on Windows.

The script logs in via smb, searches for eZip32 in the registry
and gets the version from the registry." );
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
	key = "SOFTWARE\\ediSys\\eZip32\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\ediSys\\eZip32\\";
	}
}
ezipVer = registry_get_sz( key: key, item: "Version" );
if(ezipVer != NULL){
	appPath = "Could not find the install Location from registry";
	set_kb_item( name: "eZip/Version", value: ezipVer );
	cpe = build_cpe( value: ezipVer, exp: "^([0-9.]+)", base: "cpe:/a:edisys:ezip_wizard:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:edisys:ezip_wizard";
	}
	register_product( cpe: cpe, location: appPath );
	log_message( data: build_detection_report( app: "eZip Wizard", version: ezipVer, install: appPath, cpe: cpe, concluded: ezipVer ) );
}

