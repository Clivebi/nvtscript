if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817744" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_cve_id( "CVE-2021-26424", "CVE-2021-26425", "CVE-2021-34480", "CVE-2021-34483", "CVE-2021-34484", "CVE-2021-34533", "CVE-2021-34535", "CVE-2021-34537", "CVE-2021-36927", "CVE-2021-36936", "CVE-2021-36937", "CVE-2021-36942", "CVE-2021-36947" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-20 19:04:00 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 13:34:32 +0530 (Wed, 11 Aug 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB5005088)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB5005088" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Common Log File System Driver.

  - A security feature bypass vulnerability in Kerberos AppContainer.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to perform remote code execution, gain access to potentially sensitive data,
  conduct spoofing and elevate privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit Systems Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5005088" );
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
if(hotfix_check_sp( win2008r2: 2, win7x64: 2, win7: 2 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "advapi32.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.1.7601.25682" )){
	report = report_fixed_ver( file_checked: dllPath + "\\advapi32.dll", file_version: fileVer, vulnerable_range: "Less than 6.1.7601.25682" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

