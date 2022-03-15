if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805481" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-03-20 15:38:22 +0530 (Fri, 20 Mar 2015)" );
	script_name( "Samsung iPOLiS Device Manager Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Samsung iPOLiS Device Manager.

  The script logs in via smb, searches for string 'iPOLiS Device Manager' in
  the registry and reads the version information from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
for item in registry_enum_keys( key: key ) {
	ipolisName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( ipolisName, "iPOLiS Device Manager" )){
		Ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
		iver = eregmatch( pattern: "([0-9.]+)", string: Ver );
		if(iver[1]){
			vers = iver[1];
		}
		ipolisPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!ipolisPath){
			ipolisPath = "Couldn find the install location from registry";
		}
		if(vers){
			set_kb_item( name: "Samsung/iPOLiS_Device_Manager/Win/Ver", value: vers );
			cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:samsung:ipolis_device_manager:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:samsung:ipolis_device_manager";
			}
			register_product( cpe: cpe, location: ipolisPath );
			log_message( data: build_detection_report( app: "iPOLiS Device Manager", version: vers, install: ipolisPath, cpe: cpe, concluded: vers ) );
			exit( 0 );
		}
	}
}

