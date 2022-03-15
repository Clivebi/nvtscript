if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112156" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-01-04 09:35:57 +0100 (Thu, 04 Jan 2018)" );
	script_name( "IKARUS anti.virus Detection (Windows)" );
	script_tag( name: "summary", value: "Detection of the installed version of IKARUS anti.virus.

  The script logs in via SMB, searches for the installation of 'IKARUS anti.virus' in the registry
  and tries to obtain the version information." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/Windows/Arch" );
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
if(isnull( key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	product = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( product, "IKARUS anti.virus" )){
		set_kb_item( name: "ikarus/anti.virus/detected", value: TRUE );
		version = "unknown";
		installed = TRUE;
		ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
		path = registry_get_sz( key: key + item, item: "InstallLocation" );
		break;
	}
}
if(installed){
	if(ver){
		version = ver;
		set_kb_item( name: "ikarus/anti.virus/version", value: version );
	}
	if(!path){
		if(!path = registry_get_sz( key: "SOFTWARE\\Ikarus\\guardx", item: "MainPath" )){
			path = "Could not get the install location from the registry";
		}
	}
	register_and_report_cpe( app: "IKARUS anti.virus", ver: version, base: "cpe:/a:ikarus:anti.virus:", expr: "^([0-9.]+)", insloc: path );
}
exit( 0 );

