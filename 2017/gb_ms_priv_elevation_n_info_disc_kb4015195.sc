if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810925" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2017-0058", "CVE-2017-0155" );
	script_bugtraq_id( 97462, 97471 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-12 17:38:58 +0530 (Wed, 12 Apr 2017)" );
	script_name( "Microsoft Privilege Elevation And Information Disclosure Vulnerabilities (KB4015195)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft security update KB4015195." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The win32k component improperly provides kernel information.

  - The Microsoft Graphics Component fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode. An attacker could then install programs.
  View, change, or delete data, or create new accounts with full user rights and
  obtain information to further compromise the users system." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-gb/help/4015195" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win2008: 3, winVistax64: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
winVer = fetch_file_version( sysPath: sysPath, file_name: "Win32k.sys" );
if(!winVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0){
	if( version_is_less( version: winVer, test_version: "6.0.6002.19749" ) ){
		Vulnerable_range = "Less than 6.0.6002.19749";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: winVer, test_version: "6.0.6002.24000", test_version2: "6.0.6002.24071" )){
			Vulnerable_range = "6.0.6002.24000 - 6.0.6002.24071";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "Win32k.sys" + "\n" + "File version:     " + winVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

