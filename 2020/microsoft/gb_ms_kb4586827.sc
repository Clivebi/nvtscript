if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817539" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-1599", "CVE-2020-16997", "CVE-2020-17000", "CVE-2020-17001", "CVE-2020-17004", "CVE-2020-17011", "CVE-2020-17014", "CVE-2020-17029", "CVE-2020-17036", "CVE-2020-17038", "CVE-2020-17042", "CVE-2020-17043", "CVE-2020-17044", "CVE-2020-17045", "CVE-2020-17047", "CVE-2020-17051", "CVE-2020-17052", "CVE-2020-17068", "CVE-2020-17069", "CVE-2020-17087", "CVE-2020-17088" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-23 13:57:00 +0000 (Mon, 23 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 15:13:39 +0530 (Wed, 11 Nov 2020)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4586827)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4586827" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Incorrect processing of user-supplied data in Windows.

  - Error in excessive data output by the application in Windows Graphics Component.

  - Windows Port Class Library fails to properly impose security restrictions.

  - Windows Print Spooler fails to properly impose security restrictions.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges and disclose sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit Systems Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4586827" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
fileVer = "";
dllPath = "";
report = "";
if(hotfix_check_sp( win2008r2: 2, win7x64: 2, win7: 2 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "Kernel32.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.1.7601.24562" )){
	report = report_fixed_ver( file_checked: dllPath + "\\Kernel32.dll", file_version: fileVer, vulnerable_range: "Less than 6.1.7601.24562" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );
