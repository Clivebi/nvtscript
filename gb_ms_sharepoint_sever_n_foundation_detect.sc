if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802904" );
	script_version( "$Revision: 10902 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-02 12:28:34 +0530 (Mon, 02 Jul 2012)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft SharePoint Server and Foundation Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft SharePoint Server and
Microsoft SharePoint Foundation.

The script logs in via smb, searches through the registry and gets the
version and sets the KB." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	if(spName = registry_get_sz( key: key + item, item: "DisplayName" )){
		if(ContainsString( spName, "Microsoft SharePoint Server" ) || ContainsString( spName, "Microsoft Office SharePoint Server" )){
			spVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(spVer){
				insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insPath){
					insPath = "Could not find the install location from registry";
				}
				set_kb_item( name: "MS/SharePoint/Server_or_Foundation_or_Services/Installed", value: TRUE );
				set_kb_item( name: "MS/SharePoint/Server/Ver", value: spVer );
				cpe = build_cpe( value: spVer, exp: "^([0-9.]+[a-z0-9]*)", base: "cpe:/a:microsoft:sharepoint_server:" );
				if(!cpe){
					cpe = "cpe:/a:microsoft:sharepoint_server";
				}
				register_product( cpe: cpe, location: insPath );
				log_message( data: build_detection_report( app: spName, version: spVer, install: insPath, cpe: cpe, concluded: spVer ) );
			}
		}
		if(ContainsString( spName, "Microsoft SharePoint Foundation" )){
			fdVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(fdVer){
				insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insPath){
					insPath = "Could not find the install location from registry";
				}
				set_kb_item( name: "MS/SharePoint/Foundation/Ver", value: fdVer );
				set_kb_item( name: "MS/SharePoint/Server_or_Foundation_or_Services/Installed", value: TRUE );
				cpe = build_cpe( value: fdVer, exp: "^([0-9.]+[a-z0-9]*)", base: "cpe:/a:microsoft:sharepoint_foundation:" );
				if(!cpe){
					cpe = "cpe:/a:microsoft:sharepoint_foundation";
				}
				register_product( cpe: cpe, location: insPath );
				log_message( data: build_detection_report( app: spName, version: fdVer, install: insPath, cpe: cpe, concluded: fdVer ) );
			}
		}
		if(ContainsString( spName, "Microsoft Windows SharePoint Services" )){
			spVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(spVer){
				insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!insPath){
					insPath = "Could not find the install location from registry";
				}
				set_kb_item( name: "MS/SharePoint/Services/Ver", value: spVer );
				set_kb_item( name: "MS/SharePoint/Server_or_Foundation_or_Services/Installed", value: TRUE );
				cpe = build_cpe( value: spVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:sharepoint_services:" );
				if(!cpe){
					cpe = "cpe:/a:microsoft:sharepoint_services";
				}
				register_product( cpe: cpe, location: insPath );
				log_message( data: build_detection_report( app: spName, version: spVer, install: insPath, cpe: cpe, concluded: spVer ) );
			}
		}
	}
}

