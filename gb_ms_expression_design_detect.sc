if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802707" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11015 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-14 11:53:40 +0530 (Wed, 14 Mar 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft Expression Design Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Expression Design.

The script logs in via smb, searches for Microsoft Expression Design in the
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
if(!( registry_key_exists( key: "SOFTWARE\\Microsoft\\Expression\\Design" ) )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	designName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( designName, "Microsoft Expression Design" )){
		ver = registry_get_dword( key: key + item, item: "Version" );
		if(ver){
			designPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			designVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(designVer){
				set_kb_item( name: "MS/Expression/Install/Path", value: designPath );
				set_kb_item( name: "MS/Expression/Design/Ver", value: designVer );
				cpe = build_cpe( value: designVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:expression_design:" );
				if(!isnull( cpe )){
					register_product( cpe: cpe, location: designPath );
				}
				log_message( data: "Detected Microsoft Expression Design version: " + designVer + "\nLocation: " + designPath + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + "Microsoft Expression Design " + designVer );
			}
		}
	}
}

