if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812290" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-0744", "CVE-2018-0746", "CVE-2018-0747", "CVE-2018-0748", "CVE-2018-0749", "CVE-2018-0751", "CVE-2018-0752", "CVE-2018-0753", "CVE-2018-0754", "CVE-2018-0758", "CVE-2018-0762", "CVE-2018-0766", "CVE-2018-0767", "CVE-2018-0769", "CVE-2018-0770", "CVE-2018-0772", "CVE-2018-0776", "CVE-2018-0777", "CVE-2018-0780", "CVE-2018-0781", "CVE-2018-0803", "CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754", "CVE-2018-0764", "CVE-2018-0786" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-04 15:51:45 +0530 (Thu, 04 Jan 2018)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4056888)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4056888" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Microsoft Edge does not properly enforce cross-domain policies.

  - The scripting engine handles objects in memory in Microsoft Edge.

  - The scripting engine handles objects in memory in Microsoft Browsers.

  - Windows Adobe Type Manager Font Driver (ATMFD.dll) fails to properly
    handle objects in memory.

  - Microsoft Edge PDF Reader improperly handles objects in memory.

  - Windows kernel fails to properly handle objects in memory.

  - An error in the way that the Windows Kernel API enforces permissions.

  - An error in the Microsoft Server Message Block (SMB) Server when an attacker
    with valid credentials attempts to open a specially crafted file over the SMB
    protocol on the same machine.

  - An error in the Windows kernel.

  - Multiple errors leading to 'speculative execution side-channel attacks' that
    affect many modern processors and operating systems including Intel, AMD, and ARM.

  - .NET, and .NET core, improperly process XML documents.

  - Microsoft .NET Framework (and .NET Core) components do not completely validate
    certificates." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to elevate privileges, execute arbitrary code in the context of the current
  user, potentially read data that was not intended to be disclosed, impersonate
  processes, interject cross-process communication, or interrupt system
  functionality, bypass certain security checks in the operating system, could
  cause a denial of service against a .NET application and can cause a target
  system to stop responding and can be used to read the content of memory
  across a trusted boundary and can therefore lead to information disclosure
  and some unspecified impacts too." );
	script_tag( name: "affected", value: "Microsoft Windows 10 Version 1511 x32/x64." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4056888" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
if(version_in_range( version: edgeVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.1355" )){
	report = "File checked:     " + sysPath + "\\Edgehtml.dll" + "\n" + "File version:     " + edgeVer + "\n" + "Vulnerable range: 11.0.10586.0 - 11.0.10586.1355\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

