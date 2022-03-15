if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805546" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-05-06 11:01:01 +0530 (Wed, 06 May 2015)" );
	script_name( "IBM WebSphere MQ Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of IBM WebSphere MQ.

The script logs in via smb, searches for 'IBM WebSphere MQ' in the registry and gets the version from registry." );
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
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key_list = make_list( "SOFTWARE\\IBM\\WebSphere MQ\\Installation\\Installation1" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\IBM\\WebSphere MQ\\Installation\\Installation1",
			 "SOFTWARE\\Wow6432Node\\IBM\\WebSphere MQ\\Installation\\Installation1" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		mqName = registry_get_sz( key: key, item: "ProgramFolder" );
		if(ContainsString( mqName, "IBM WebSphere MQ" ) || ContainsString( mqName, "IBM MQ" )){
			mqVer = registry_get_sz( key: key, item: "BuildDate" );
			mqVer = eregmatch( pattern: "version ([0-9.]+)", string: mqVer );
			if(!isnull( mqVer[1] )){
				mqVer = mqVer[1];
				mqPath = registry_get_sz( key: key, item: "FilePath" );
				if(!mqPath){
					mqPath = "Couldn find the install location from registry";
				}
				set_kb_item( name: "ibm_websphere_mq/detected", value: TRUE );
				if( ContainsString( os_arch, "64" ) ){
					set_kb_item( name: "ibm_websphere_mq/win/x64/version", value: mqVer );
					set_kb_item( name: "ibm_websphere_mq/win/x64/path", value: mqPath );
				}
				else {
					set_kb_item( name: "ibm_websphere_mq/win/x86/version", value: mqVer );
					set_kb_item( name: "ibm_websphere_mq/win/x86/path", value: mqPath );
				}
				exit( 0 );
			}
		}
	}
}
exit( 0 );

