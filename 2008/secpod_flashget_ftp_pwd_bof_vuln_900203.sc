if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900203" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)" );
	script_cve_id( "CVE-2008-4321" );
	script_bugtraq_id( 30685 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_name( "FlashGet FTP PWD Response Remote Buffer Overflow Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2381" );
	script_tag( name: "summary", value: "FlashGet is prone to a remote buffer overflow vulnerability." );
	script_tag( name: "insight", value: "Error exists when handling overly long FTP PWD responses." );
	script_tag( name: "affected", value: "FlashGet 1.9 (1.9.6.1073) and prior versions on Windows (All)." );
	script_tag( name: "solution", value: "Update to version 3.3 or later." );
	script_tag( name: "impact", value: "Successful exploitation will allow execution of arbitrary code
  by tricking a user into connecting to a malicious ftp server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for entry in registry_enum_keys( key: key ) {
	if(ContainsString( entry, "FlashGet(Jetcar)" ) || ContainsString( entry, "FlashGet(JetCar)" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
	if(ContainsString( entry, "FlashGet" )){
		flashVer = registry_get_sz( item: "DisplayVersion", key: key + entry );
		if(flashVer && egrep( pattern: "^(1\\.9|1\\.9\\.[0-5](\\..*)?|1\\.9\\.6(\\.(0?[0-9]?[0-9]?[0-9]|10[0-6][0-9]|107[0-3]))?)$", string: flashVer )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
		exit( 99 );
	}
}
exit( 0 );

