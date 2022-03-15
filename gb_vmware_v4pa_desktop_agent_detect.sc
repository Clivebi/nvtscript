if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812788" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-03-06 11:00:32 +0530 (Tue, 06 Mar 2018)" );
	script_name( "Vmware vRealize Operations Published Applications (V4PA) Desktop Agent Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Vmware V4PA Desktop Agent.

  The script logs in via smb, searches for 'vRealize Operations for Published
  Applications' in the registry, gets version and installation path information
  from the registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\VMware, Inc.\\vRealize Operations for Published Apps\\Desktop Agent" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\VMware, Inc.\\vRealize Operations for Published Apps\\Desktop Agent" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\VMware, Inc.\\vRealize Operations for Published Apps\\Desktop Agent" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\VMware, Inc.\\vRealize Operations for Published Apps\\Desktop Agent",
			 "SOFTWARE\\Wow6432Node\\VMware, Inc.\\vRealize Operations for Published Apps\\Desktop Agent" );
	}
}
for vmkey in key_list {
	vmVer = registry_get_sz( key: vmkey, item: "ProductVersion" );
	vmPath = registry_get_sz( key: vmkey, item: "VMToolsPath" );
	if(!vmPath){
		vmPath = "Couldn find the install location from registry";
	}
	if(vmVer){
		set_kb_item( name: "vmware/V4PA/DesktopAgent/Win/Ver", value: vmVer );
		cpe = build_cpe( value: vmVer, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vrealize_operations_for_published_applications:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:vmware:vrealize_operations_for_published_applications";
		}
		if(ContainsString( os_arch, "x64" ) && !ContainsString( vmkey, "Wow6432Node" )){
			set_kb_item( name: "vmware/V4PA/DesktopAgent64/Win/Ver", value: vmVer );
			cpe = build_cpe( value: vmVer, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vrealize_operations_for_published_applications:x64:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:vmware:vrealize_operations_for_published_applications:x64";
			}
		}
		register_product( cpe: cpe, location: vmPath );
		log_message( data: build_detection_report( app: "vmware vRealize Operations for Published Apps Desktop Agent", version: vmVer, install: vmPath, cpe: cpe, concluded: vmVer ) );
	}
}
exit( 0 );

