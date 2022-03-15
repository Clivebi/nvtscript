if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815834" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2018-12207", "CVE-2019-0712", "CVE-2019-0719", "CVE-2019-11135", "CVE-2019-1380", "CVE-2019-1381", "CVE-2019-1382", "CVE-2019-1383", "CVE-2019-1384", "CVE-2019-1388", "CVE-2019-1389", "CVE-2019-1390", "CVE-2019-1391", "CVE-2019-1392", "CVE-2019-1393", "CVE-2019-1394", "CVE-2019-1395", "CVE-2019-1396", "CVE-2019-1397", "CVE-2019-1405", "CVE-2019-1406", "CVE-2019-1407", "CVE-2019-1408", "CVE-2019-1409", "CVE-2019-1411", "CVE-2019-1415", "CVE-2019-1417", "CVE-2019-1418", "CVE-2019-1419", "CVE-2019-1420", "CVE-2019-1422", "CVE-2019-1424", "CVE-2019-1426", "CVE-2019-1429", "CVE-2019-1433", "CVE-2019-1434", "CVE-2019-1435", "CVE-2019-1436", "CVE-2019-1438", "CVE-2019-1439", "CVE-2019-1456" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-13 09:04:24 +0530 (Wed, 13 Nov 2019)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4525232)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4525232" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - Windows Installer improperly handles certain filesystem operations.

  - Windows Universal Plug and Play (UPnP) service improperly allows COM
    object creation.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows Graphics Component improperly handles objects in memory.

  - Scripting engine improperly handles objects in memory in Internet Explorer.

  - Windows Netlogon improperly handles a secure communications channel.

  - Windows Win32k component fails to properly handle objects in memory.

  Please see the references for more information about the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to crash the host server, execute code with elevated permissions, bypass security
  restrictions, and disclose sensitive information to further compromise the user's
  system." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4525232" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
dllVer = fetch_file_version( sysPath: sysPath, file_name: "Crypt32.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_in_range( version: dllVer, test_version: "10.0.10240.0", test_version2: "10.0.10240.18394" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Crypt32.dll", file_version: dllVer, vulnerable_range: "10.0.10240.0 - 10.0.10240.18394" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

