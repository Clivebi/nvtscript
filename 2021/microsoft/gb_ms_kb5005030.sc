if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817739" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-26424", "CVE-2021-26425", "CVE-2021-26426", "CVE-2021-26432", "CVE-2021-26433", "CVE-2021-34480", "CVE-2021-34483", "CVE-2021-34484", "CVE-2021-34486", "CVE-2021-34487", "CVE-2021-34530", "CVE-2021-34533", "CVE-2021-34534", "CVE-2021-34535", "CVE-2021-34536", "CVE-2021-34537", "CVE-2021-36926", "CVE-2021-36932", "CVE-2021-36933", "CVE-2021-36936", "CVE-2021-36937", "CVE-2021-36938", "CVE-2021-36942", "CVE-2021-36947", "CVE-2021-36948" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-23 11:59:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 12:22:22 +0530 (Wed, 11 Aug 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB5005030)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB5005030" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Windows Media.

  - An error in Windows Projected File System.

  - An error in Windows DNS Server.

  - An error in Windows DNS Snap-in.

  - An error in Windows Kernel.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct DoS, bypass security restrictions, perform remote code execution,
  gain access to potentially sensitive data, conduct spoofing and elevate privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5005030" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1, win2019: 1 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "mshtml.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_in_range( version: fileVer, test_version: "11.0.17763.0", test_version2: "11.0.17763.2113" )){
	report = report_fixed_ver( file_checked: dllPath + "\\mshtml.dll", file_version: fileVer, vulnerable_range: "11.0.17763.0 - 11.0.17763.2113" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

