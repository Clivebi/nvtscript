if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801853" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Citrix License Server Version Detection" );
	script_tag( name: "summary", value: "This script finds the installed Citrix License Server version.

  The script logs in via smb, searches for Citrix in the registry and gets the
  version from 'Version' string from the registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
	key_list = make_list( "SOFTWARE\\Citrix\\LicenseServer\\Install" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Citrix\\LicenseServer\\Install" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Citrix\\LicenseServer" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Citrix\\LicenseServer" )){
		exit( 0 );
	}
}
for key in key_list {
	ciVer = registry_get_sz( key: key, item: "Version" );
	if(ciVer){
		ciPath = registry_get_sz( key: key, item: "LS_Install_Dir" );
		if(!ciPath){
			ciPath = "Couldn find the install location from registry";
		}
		set_kb_item( name: "Citrix/License/Server/Ver", value: ciVer );
		cpe = build_cpe( value: ciVer, exp: "^([0-9.]+)", base: "cpe:/a:citrix:licensing_administration_console:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:citrix:licensing_administration_console";
		}
		register_product( cpe: cpe, location: ciPath );
		log_message( data: build_detection_report( app: "Citrix License Server", version: ciVer, install: ciPath, cpe: cpe, concluded: ciVer ) );
	}
}

