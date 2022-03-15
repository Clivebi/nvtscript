if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802299" );
	script_version( "$Revision: 14329 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IBM SPSS SamplePower Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of IBM SPSS SamplePower on Windows.

The script logs in via smb, searches for IBM SPSS SamplePower in the registry,
gets the from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		gsName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( gsName, "SamplePower" )){
			gsVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(gsVer){
				path = registry_get_sz( key: key + item, item: "Readme" );
				if(!path){
					path = "Could not find the install location from registry";
				}
				set_kb_item( name: "IBM/SPSS/Win/Installed", value: TRUE );
				if( ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "IBM/SPSS64/Win/Ver", value: gsVer );
					register_and_report_cpe( app: "IBM SPSS SamplePower", ver: gsVer, base: "cpe:/a:ibm:spss_samplepower:x64:", expr: "^([0-9.]+)", insloc: path );
				}
				else {
					set_kb_item( name: "IBM/SPSS/Win/Ver", value: gsVer );
					register_and_report_cpe( app: "IBM SPSS SamplePower", ver: gsVer, base: "cpe:/a:ibm:spss_samplepower:", expr: "^([0-9.]+)", insloc: path );
				}
			}
		}
	}
}

