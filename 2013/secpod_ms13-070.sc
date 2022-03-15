if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901220" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3863" );
	script_bugtraq_id( 62178 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 08:16:49 +0530 (Wed, 11 Sep 2013)" );
	script_name( "Microsoft Windows OLE Remote Code Execution Vulnerability (2876217)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to Microsoft
Bulletin MS13-070." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Flaw is caused when Microsoft Windows incorrectly handles OLE objects in
memory." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code and
take complete control of an affected system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2876217" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-070" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ole32.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "5.1.2600.6435" )){
		report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.6435", install_path: sysPath );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}
else {
	if(hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0){
		if(version_is_less( version: sysVer, test_version: "5.2.3790.5209" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.5209", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
}

