if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802746" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-04-13 10:46:45 +0530 (Fri, 13 Apr 2012)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Forefront Unified Access Gateway (UAG) Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Forefront Unified Access Gateway.

The script logs in via smb, searches for Microsoft Forefront Unified Access
Gateway in the registry and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
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
if(!osArch){
	exit( 0 );
}
if(!ContainsString( os_arch, "x64" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	uagName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(!uagName){
		continue;
	}
	if(ContainsString( uagName, "Microsoft Forefront Unified Access Gateway" )){
		uagVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(uagVer){
			set_kb_item( name: "MS/Forefront/UAG/Ver", value: uagVer );
			cpe = build_cpe( value: uagVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:forefront_unified_access_gateway:" );
			insPath = "Could not determine InstallLocation from Registry\n";
			if(cpe){
				register_product( cpe: cpe, location: insPath );
			}
			log_message( data: "Detected MS Forefront Unified Access Gateway version: " + uagVer + "\nLocation: " + insPath + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + "MS ForefrontUnified Access Gateway " + uagVer );
		}
	}
}

