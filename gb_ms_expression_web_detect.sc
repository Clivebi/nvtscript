if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802885" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-11 18:35:57 +0530 (Wed, 11 Jul 2012)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Expression Web Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Expression Web.

The script logs in via smb, searches for Microsoft Expression Web and
in the registry and gets the version from 'Version' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	ewName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( ewName, "Microsoft Expression Web" )){
		ewVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(ewVer){
			insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insPath){
				insPath = "Could not find the install location from registry";
			}
			set_kb_item( name: "MS/Expression-Web/Ver", value: ewVer );
			cpe = build_cpe( value: ewVer, exp: "^([0-9.]+[a-z0-9]*)", base: "cpe:/a:microsoft:expression_web:" );
			if(!cpe){
				cpe = "cpe:/a:microsoft:expression_web";
			}
			register_product( cpe: cpe, location: insPath );
			log_message( data: build_detection_report( app: "Microsoft Expression Web", version: ewVer, install: insPath, cpe: cpe, concluded: ewVer ) );
		}
	}
}

