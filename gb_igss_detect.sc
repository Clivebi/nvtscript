if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802240" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "7-Technologies Interactive Graphical SCADA System Version Detection" );
	script_tag( name: "summary", value: "This script finds the installed Interactive Graphical SCADA System version.

The script logs in via smb, searches for 'IGSS32' String in the registry and
gets the version from registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\7-Technologies\\IGSS32" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\7-Technologies\\IGSS32" )){
		exit( 0 );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		igssname = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( igssname, "IGSS32" )){
			igssversion = registry_get_sz( key: key + item, item: "DisplayVersion" );
			igssPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!igssPath){
				igssPath = "Couldn find the install location from registry.";
			}
			if(igssversion){
				set_kb_item( name: "IGSS/Win/Ver", value: igssversion );
				cpe = build_cpe( value: igssversion, exp: "^([0-9.]+)", base: "cpe:/a:7t:igss:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:7t:igss";
				}
				register_product( cpe: cpe, location: igssPath );
				log_message( data: build_detection_report( app: "Interactive Graphical SCADA System", version: igssversion, install: igssPath, cpe: cpe, concluded: igssversion ) );
			}
		}
	}
}

