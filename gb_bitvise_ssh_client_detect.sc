if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813385" );
	script_version( "2019-07-25T12:21:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 12:21:33 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)" );
	script_name( "Bitvise SSH Client Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Bitvise SSH Client.

  The script logs in via smb, searches for 'Bitvise SSH Client' in the
  registry, gets version and installation path information from the registry." );
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
	bitName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( bitName, "Bitvise SSH Client" )){
		bitPath = registry_get_sz( key: key + item, item: "InstallSource" );
		if(!bitPath){
			bitPath = "Couldn find the install location";
		}
		bitVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(bitVer){
			set_kb_item( name: "BitviseSSH/Client/Win/Ver", value: bitVer );
			cpe = build_cpe( value: bitVer, exp: "^([0-9.]+)", base: "cpe:/a:bitvise:ssh_client:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:bitvise:ssh_client";
			}
			register_product( cpe: cpe, location: bitPath );
			log_message( data: build_detection_report( app: "Bitvise SSH Client", version: bitVer, install: bitPath, cpe: cpe, concluded: "Bitvise SSH Client " + bitVer ) );
		}
	}
}
exit( 0 );

