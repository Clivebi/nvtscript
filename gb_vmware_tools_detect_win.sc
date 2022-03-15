if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809030" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-02 13:07:24 +0530 (Fri, 02 Sep 2016)" );
	script_name( "VMware Tools Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  VMware Tools.

  The script logs in via smb, searches registry for VMware Tools
  and gets the version from 'DisplayVersion' string." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\VMware, Inc.\\VMware Tools" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\VMware, Inc.\\VMware Tools" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		vmtoolName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( vmtoolName, "VMware Tools" )){
			vmtoolVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(vmtoolVer){
				vmtoolPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!vmtoolPath){
					vmtoolPath = "Unable to find the install location from registry";
				}
				set_kb_item( name: "VMwareTools/Win/Ver", value: vmtoolVer );
				cpe = build_cpe( value: vmtoolVer, exp: "^([0-9.]+)", base: "cpe:/a:vmware:tools:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:vmware:tools";
				}
				register_product( cpe: cpe, location: vmtoolPath );
				log_message( data: build_detection_report( app: "VMware Tools", version: vmtoolVer, install: vmtoolPath, cpe: cpe, concluded: vmtoolVer ) );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

