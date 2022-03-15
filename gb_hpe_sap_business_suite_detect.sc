if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809435" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-10-17 16:22:36 +0530 (Mon, 17 Oct 2016)" );
	script_name( "HPE Sizing Tool for SAP Business Suite Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  HPE Sizing Tool for SAP Business Suite.

  The script logs in via smb, searches for 'HPE Sizing Tool for SAP Business Suite'
  in the registry, gets version and installation path information from the registry." );
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
if(!registry_key_exists( key: "SOFTWARE\\Hewlett Packard Enterprise\\Sizers\\SAP HANA Sizing Tool" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Hewlett Packard Enterprise\\Sizers\\SAP HANA Sizing Tool" )){
	exit( 0 );
}
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
	hpName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( hpName, "HPE sizing tool for SAP Business Suite" )){
		hpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(hpVer){
			hpPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!hpPath){
				hpPath = "Couldn find the install location from registry";
			}
			set_kb_item( name: "HPE/Sizing/Tool/SAP/Sizing/Suite/Win/Ver", value: hpVer );
			cpe = build_cpe( value: hpVer, exp: "^([0-9.]+)", base: "cpe:/a:hp:sizing_tool_for_sap_business_suite_powered_by_hana:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:hp:sizing_tool_for_sap_business_suite_powered_by_hana";
			}
			register_product( cpe: cpe, location: hpPath );
			log_message( data: build_detection_report( app: "HPE Sizing Tool for SAP Business Suite", version: hpVer, install: hpPath, cpe: cpe, concluded: hpVer ) );
		}
	}
}

