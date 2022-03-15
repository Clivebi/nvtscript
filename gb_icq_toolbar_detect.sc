if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800693" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ICQ Toolbar version detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of ICQ Toolbar." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "ICQ Toolbar version detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
Key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: Key )){
	exit( 0 );
}
for item in registry_enum_keys( key: Key ) {
	icqName = registry_get_sz( key: Key + item, item: "DisplayName" );
	if(ContainsString( icqName, "ICQ" )){
		path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\", item: "ProgramFilesDir" );
		for file in make_list( "\\ICQToolbar\\version.txt",
			 "\\ICQ6Toolbar\\version.txt" ) {
			icqVer = smb_read_file( fullpath: path + file, offset: 0, count: 25 );
			icqVer = ereg_replace( pattern: "[-| ]", replace: ".", string: icqVer );
			if(icqVer){
				set_kb_item( name: "ICQ/Toolbar/Ver", value: icqVer );
				log_message( data: "ICQ Toolbar version " + icqVer + " was detected on the host" );
				cpe = build_cpe( value: icqVer, exp: "^([0-9.]+)", base: "cpe:/a:icq:icq_toolbar:" );
				if(!isnull( cpe )){
					register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
				}
			}
		}
	}
}

