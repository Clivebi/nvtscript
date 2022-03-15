if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804587" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-05-15 15:17:33 +0530 (Thu, 15 May 2014)" );
	script_name( "Microsoft .NET Framework 'RC4' Information Disclosure Vulnerability (2960358)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Security Advisory 2960358." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the RC4 encryption algorithm is used in Transport
  Layer Security (TLS)." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to perform man-in-the-middle
  attacks and recover plaintext from encrypted sessions." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 3.5, 3.5.1, 4.0 and 4.5 and 4.5.X." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2960358" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/2960358" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8: 1, win8_1: 1, win8_1x64: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "system.dll" );
		if(dllVer){
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34110" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36117" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34110" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36112" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34113" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36116" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1023" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2037" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5483" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7057" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6416" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7057" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8003" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8606" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

