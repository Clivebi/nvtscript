if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801272" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Google Earth Version Detection" );
	script_tag( name: "summary", value: "This script finds the installed Google Earth version.

The script logs in via smb, searches for Google Earth in the registry
and gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
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
if(isnull( key_list )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Google\\GoogleEarthPlugin\\" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Google\\GoogleEarthPlugin\\" )){
		exit( 0 );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		geName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( geName, "Google Earth" )){
			geVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(geVer){
				gePath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!gePath){
					gePath = "Couldn find the install location from registry";
				}
				set_kb_item( name: "Google/Earth/Ver", value: geVer );
				cpe = build_cpe( value: geVer, exp: "^([0-9.]+)", base: "cpe:/a:google:earth:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:google:earth";
				}
				register_product( cpe: cpe, location: gePath );
				log_message( data: build_detection_report( app: "Google Earth", version: geVer, install: gePath, cpe: cpe, concluded: geVer ) );
			}
		}
	}
}

