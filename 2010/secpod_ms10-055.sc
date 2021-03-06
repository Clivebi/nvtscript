if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900249" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)" );
	script_bugtraq_id( 42256 );
	script_cve_id( "CVE-2010-2553" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Remote Code Execution Vulnerability in Cinepak Codec (982665)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/982665" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-055" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code with the privileges of the user running the application." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista service Pack 2 and prior

  - Microsoft Windows 7" );
	script_tag( name: "insight", value: "The Cinepak Codec applications fails to perform adequate boundary checks
  while handling supported format files." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-055." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, winVista: 3, win7: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "982665" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Iccvid.dll" );
	if(!dllVer){
		exit( 0 );
	}
	if(hotfix_check_sp( xp: 4 ) > 0){
		if(version_is_less( version: dllVer, test_version: "1.10.0.13" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "1.10.0.13", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "iccvid.dll" );
if(!dllVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win7: 1 ) > 0){
	if(version_is_less( version: dllVer, test_version: "1.10.0.13" )){
		report = report_fixed_ver( installed_version: dllVer, fixed_version: "1.10.0.13", install_path: sysPath );
		security_message( port: 0, data: report );
	}
}

