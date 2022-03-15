if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804108" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-15 20:26:57 +0530 (Tue, 15 Oct 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Corel PDF Fusion Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Corel PDF Fusion on Windows.

The script logs in via smb, searches for Corel PDF Fusion in the registry
and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(IsMatchRegexp( appName, "^Corel PDF Fusion$" )){
			pdfVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(pdfVer){
				insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insPath){
					insPath = "Could not find the install location from registry";
				}
				set_kb_item( name: "Corel/PDF/Fusion/Win/Ver", value: pdfVer );
				cpe = build_cpe( value: pdfVer, exp: "^([0-9.]+)", base: "cpe:/a:corel:pdf_fusion:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:corel:pdf_fusion";
				}
				register_product( cpe: cpe, location: insPath );
				log_message( data: build_detection_report( app: appName, version: pdfVer, install: insPath, cpe: cpe, concluded: pdfVer ) );
			}
		}
	}
}

