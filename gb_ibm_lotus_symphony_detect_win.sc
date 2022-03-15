if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802226" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IBM Lotus Symphony Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of IBM Lotus Symphony on Windows.

The script logs in via smb, searches for IBM Lotus Symphony in the registry,
gets the from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Lotus\\Symphony" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Lotus\\Symphony" )){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		gsName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( gsName, "IBM Lotus Symphony" )){
			gsVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(gsVer){
				path = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!path){
					path = "Could not find the install location from registry";
				}
				set_kb_item( name: "IBM/Lotus/Symphony/Win/Ver", value: gsVer );
				cpe = build_cpe( value: gsVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:lotus_symphony:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:ibm:lotus_symphony";
				}
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "IBM/Lotus/Symphony64/Win/Ver", value: gsVer );
					cpe = build_cpe( value: gsVer, exp: "^([0-9.]+)", base: "cpe:/a:ibm:lotus_symphony:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:ibm:lotus_symphony:x64";
					}
				}
				register_product( cpe: cpe, location: path );
				log_message( data: build_detection_report( app: "IBM Lotus Symphony", version: gsVer, install: path, cpe: cpe, concluded: gsVer ) );
			}
		}
	}
}

