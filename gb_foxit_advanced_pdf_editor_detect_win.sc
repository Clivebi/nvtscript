if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803303" );
	script_version( "$Revision: 11356 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-02-01 18:35:32 +0530 (Fri, 01 Feb 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Foxit Advanced PDF Editor Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Foxit Advanced PDF Editor.

The script logs in via smb, searches for Foxit Advanced PDF Editor in the
registry and gets the version from registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
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
if(!registry_key_exists( key: "SOFTWARE\\Foxit Software" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Foxit Software" )){
		exit( 0 );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		FoxitName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( FoxitName, "Foxit Advanced PDF Editor" )){
			FoxitPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!FoxitPath){
				FoxitPath = "Could not find the install Location";
			}
			FoxitVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(FoxitVer){
				set_kb_item( name: "foxit/advanced_editor/win/ver", value: FoxitVer );
				cpe = build_cpe( value: FoxitVer, exp: "^([0-9.]+)", base: "cpe:/a:foxitsoftware:foxit_advanced_pdf_editor:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:foxitsoftware:foxit_advanced_pdf_editor";
				}
				register_product( cpe: cpe, location: FoxitPath );
				log_message( data: build_detection_report( app: "Foxit AdvancedPDF Editor", version: FoxitVer, install: FoxitPath, cpe: cpe, concluded: FoxitVer ) );
			}
		}
	}
}

