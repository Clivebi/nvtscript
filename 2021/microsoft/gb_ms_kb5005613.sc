if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818530" );
	script_version( "2021-09-27T08:01:28+0000" );
	script_cve_id( "CVE-2021-26435", "CVE-2021-36955", "CVE-2021-36959", "CVE-2021-36960", "CVE-2021-36961", "CVE-2021-36962", "CVE-2021-36963", "CVE-2021-36964", "CVE-2021-36965", "CVE-2021-36969", "CVE-2021-36972", "CVE-2021-36974", "CVE-2021-38624", "CVE-2021-38628", "CVE-2021-38629", "CVE-2021-38630", "CVE-2021-38633", "CVE-2021-38635", "CVE-2021-38636", "CVE-2021-38638", "CVE-2021-38639", "CVE-2021-38667", "CVE-2021-38671", "CVE-2021-40444", "CVE-2021-40447" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-27 08:01:28 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-25 11:27:00 +0000 (Sat, 25 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-15 10:25:29 +0530 (Wed, 15 Sep 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB5005613)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB5005613" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Windows WLAN AutoConfig Service.

  - An elevation of privilege vulnerability in Windows Print Spooler.

  - An elevation of privilege vulnerability in Windows Ancillary Function Driver for WinSock.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to disclose sensitive information, perform remote code execution, cause
  denial of service condition, conduct spoofing and elevate privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5005613" );
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
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "urlmon.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "11.0.9600.20120" )){
	report = report_fixed_ver( file_checked: dllPath + "\\urlmon.dll", file_version: fileVer, vulnerable_range: "Less than 11.0.9600.20120" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

