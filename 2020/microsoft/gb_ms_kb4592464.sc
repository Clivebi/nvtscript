if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817549" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-16958", "CVE-2020-16959", "CVE-2020-16960", "CVE-2020-16961", "CVE-2020-16962", "CVE-2020-16963", "CVE-2020-16964", "CVE-2020-17092", "CVE-2020-17096", "CVE-2020-17097", "CVE-2020-17098", "CVE-2020-17099", "CVE-2020-17140" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 18:26:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-09 10:50:46 +0530 (Wed, 09 Dec 2020)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4592464)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4592464" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the Backup Engine allows a local authenticated malicious
    user to gain elevated privileges on the system.

  - An error in the GDI+ component.

  - An error in the SMBv2 component.
  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to elevate privilges and disclose sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4592464" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "Ntoskrnl.exe" );
if(!dllVer){
	exit( 0 );
}
if(version_is_less( version: dllVer, test_version: "10.0.10240.18782" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Ntoskrnl.exe", file_version: dllVer, vulnerable_range: "Less than 10.0.10240.18782" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

