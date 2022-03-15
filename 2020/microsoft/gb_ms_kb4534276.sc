if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815740" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-0601", "CVE-2020-0607", "CVE-2020-0615", "CVE-2020-0617", "CVE-2020-0623", "CVE-2020-0608", "CVE-2020-0611", "CVE-2020-0613", "CVE-2020-0614", "CVE-2020-0620", "CVE-2020-0621", "CVE-2020-0622", "CVE-2020-0625", "CVE-2020-0626", "CVE-2020-0627", "CVE-2020-0628", "CVE-2020-0629", "CVE-2020-0630", "CVE-2020-0631", "CVE-2020-0632", "CVE-2020-0633", "CVE-2020-0634", "CVE-2020-0635", "CVE-2020-0638", "CVE-2020-0639", "CVE-2020-0644", "CVE-2020-0641", "CVE-2020-0642", "CVE-2020-0643", "CVE-2020-0606", "CVE-2020-0640", "CVE-2020-0605", "CVE-2020-0646" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-26 17:15:00 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-01-15 08:48:53 +0530 (Wed, 15 Jan 2020)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4534276)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4534276" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Microsoft Graphics Components improperly handles objects in memory.

  - Windows Common Log File System (CLFS) driver fails to properly handle
    objects in memory.

  - Windows Search Indexer handles objects in memory.

  - Microsoft Windows implements predictable memory section names.

  - Windows Media Service allows file creation in arbitrary locations.

  - Internet Explorer improperly accesses objects in memory.

  Please see the references for more information about the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code, bypass security features, elevate privileges,
  disclose sensitive information, conduct denial of service and spoofing attacks." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4534276" );
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
dllVer = fetch_file_version( sysPath: sysPath, file_name: "User32.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_in_range( version: dllVer, test_version: "10.0.16299.0", test_version2: "10.0.16299.1624" )){
	report = report_fixed_ver( file_checked: sysPath + "\\User32.dll", file_version: dllVer, vulnerable_range: "10.0.16299.0 - 10.0.16299.1624" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

