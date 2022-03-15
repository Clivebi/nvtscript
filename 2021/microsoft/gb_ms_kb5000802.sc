if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818016" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-1640", "CVE-2021-1729", "CVE-2021-24090", "CVE-2021-24095", "CVE-2021-24107", "CVE-2021-26411", "CVE-2021-26860", "CVE-2021-26861", "CVE-2021-26862", "CVE-2021-26863", "CVE-2021-26864", "CVE-2021-26865", "CVE-2021-26866", "CVE-2021-26867", "CVE-2021-26868", "CVE-2021-26869", "CVE-2021-26870", "CVE-2021-26871", "CVE-2021-26872", "CVE-2021-26873", "CVE-2021-26874", "CVE-2021-26875", "CVE-2021-26876", "CVE-2021-26877", "CVE-2021-26878", "CVE-2021-26879", "CVE-2021-26880", "CVE-2021-26881", "CVE-2021-26882", "CVE-2021-26884", "CVE-2021-26885", "CVE-2021-26886", "CVE-2021-26889", "CVE-2021-26890", "CVE-2021-26891", "CVE-2021-26892", "CVE-2021-26893", "CVE-2021-26894", "CVE-2021-26895", "CVE-2021-26896", "CVE-2021-26897", "CVE-2021-26898", "CVE-2021-26899", "CVE-2021-26900", "CVE-2021-26901", "CVE-2021-27063", "CVE-2021-27070", "CVE-2021-27077", "CVE-2021-27085" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-12 21:07:00 +0000 (Fri, 12 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 15:18:43 +0530 (Wed, 10 Mar 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB5000802)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB5000802" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Windows Print Spooler.

  - An error in Windows Event Tracing.

  - An memory corruption flaw in Internet Explorer.

  - An error in Windows Graphics Component.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges and disclose sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5000802" );
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
if(version_in_range( version: fileVer, test_version: "10.0.19041.0", test_version2: "10.0.19041.866" )){
	report = report_fixed_ver( file_checked: dllPath + "\\localspl.dll", file_version: fileVer, vulnerable_range: "10.0.19041.0 - 10.0.19041.866" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

