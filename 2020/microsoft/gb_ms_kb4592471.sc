if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817545" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-16958", "CVE-2020-16959", "CVE-2020-16960", "CVE-2020-16961", "CVE-2020-16962", "CVE-2020-16963", "CVE-2020-16964", "CVE-2020-17049", "CVE-2020-17098", "CVE-2020-17140" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-23 16:08:00 +0000 (Mon, 23 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-12-09 10:24:55 +0530 (Wed, 09 Dec 2020)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4592471)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4592471" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the Backup Engine allows a local authenticated malicious
    user to gain elevated privileges on the system.

  - An error in Kerberos Security Feature.

  - An error in the GDI+ component.

  - An error in the SMBv2 component.
  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to elevate privilges and disclose sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit Systems Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4592471" );
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
fileVer = fetch_file_version( sysPath: dllPath, file_name: "Localspl.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.1.7601.24563" )){
	report = report_fixed_ver( file_checked: dllPath + "\\Localspl.dll", file_version: fileVer, vulnerable_range: "Less than 6.1.7601.24563" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

