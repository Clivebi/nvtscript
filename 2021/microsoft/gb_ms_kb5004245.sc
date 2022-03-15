if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818342" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-31183", "CVE-2021-31961", "CVE-2021-31979", "CVE-2021-33743", "CVE-2021-33744", "CVE-2021-33749", "CVE-2021-33750", "CVE-2021-33751", "CVE-2021-33752", "CVE-2021-33755", "CVE-2021-33756", "CVE-2021-33757", "CVE-2021-33759", "CVE-2021-33760", "CVE-2021-33761", "CVE-2021-33763", "CVE-2021-33765", "CVE-2021-33771", "CVE-2021-33773", "CVE-2021-33774", "CVE-2021-33781", "CVE-2021-33782", "CVE-2021-33783", "CVE-2021-33784", "CVE-2021-33785", "CVE-2021-33788", "CVE-2021-34438", "CVE-2021-34440", "CVE-2021-34441", "CVE-2021-34445", "CVE-2021-34446", "CVE-2021-34447", "CVE-2021-34448", "CVE-2021-34449", "CVE-2021-34450", "CVE-2021-34454", "CVE-2021-34455", "CVE-2021-34456", "CVE-2021-34457", "CVE-2021-34459", "CVE-2021-34460", "CVE-2021-34462", "CVE-2021-34466", "CVE-2021-34476", "CVE-2021-34488", "CVE-2021-34489", "CVE-2021-34490", "CVE-2021-34491", "CVE-2021-34492", "CVE-2021-34493", "CVE-2021-34496", "CVE-2021-34497", "CVE-2021-34498", "CVE-2021-34500", "CVE-2021-34503", "CVE-2021-34504", "CVE-2021-34507", "CVE-2021-34508", "CVE-2021-34509", "CVE-2021-34510", "CVE-2021-34511", "CVE-2021-34512", "CVE-2021-34513", "CVE-2021-34514", "CVE-2021-34516", "CVE-2021-34521" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-22 17:06:00 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-14 07:51:35 +0530 (Wed, 14 Jul 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB5004245)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB5004245" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Windows TCP/IP Driver.

  - An error in Windows InstallService.

  - An error in Windows Kernel.

  - An error in Windows Projected File System.

  - An error in Windows Secure Kernel Mode.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct DoS, bypass security restrictions, perform remote code execution,
  gain access to potentially sensitive data, conduct spoofing and elevate privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5004245" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "localspl.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_in_range( version: fileVer, test_version: "10.0.18362.0", test_version2: "10.0.18362.1645" )){
	report = report_fixed_ver( file_checked: dllPath + "\\localspl.dll", file_version: fileVer, vulnerable_range: "10.0.18362.0 - 10.0.18362.1645" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );
