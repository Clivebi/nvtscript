if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814693" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-0609", "CVE-2019-0782", "CVE-2019-0783", "CVE-2019-0784", "CVE-2019-0614", "CVE-2019-0617", "CVE-2019-0797", "CVE-2019-0821", "CVE-2019-0680", "CVE-2019-0690", "CVE-2019-0695", "CVE-2019-0702", "CVE-2019-0703", "CVE-2019-0704", "CVE-2019-0746", "CVE-2019-0754", "CVE-2019-0755", "CVE-2019-0756", "CVE-2019-0759", "CVE-2019-0761", "CVE-2019-0763", "CVE-2019-0765", "CVE-2019-0767", "CVE-2019-0769", "CVE-2019-0770", "CVE-2019-0771", "CVE-2019-0772", "CVE-2019-0773", "CVE-2019-0774", "CVE-2019-0775", "CVE-2019-0776", "CVE-2019-0780", "CVE-2019-0665", "CVE-2019-0666", "CVE-2019-0667", "CVE-2019-0601" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-13 08:42:56 +0530 (Wed, 13 Mar 2019)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4489872)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4489872" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The scripting engine improperly handles objects in memory in Microsoft Edge.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows kernel improperly handles objects in memory.

  - The win32k component improperly provides kernel information.

  - The Microsoft XML Core Services MSXML parser processes user input.

  - Windows improperly handles objects in memory.

  - The Win32k component fails to properly handle objects in memory.

  - Windows Print Spooler does not properly handle objects in memory.

  - Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - Windows SMB Server does not properly handles certain requests.

  - Windows kernel improperly initializes objects in memory.

  - Internet Explorer improperly accesses objects in memory.

  - Internet Explorer fails to validate the correct Security Zone of requests
    for specific URLs.

  - Microsoft browsers improperly access objects in memory.

  - The ActiveX Data objects (ADO) improperly handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to execute arbitrary code on a victim system, obtain information
  to further compromise the user's system, gain elevated privileges, cause the
  host server to crash and bypass security restrictions." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for 32-bit Systems and

  - Microsoft Windows 10 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4489872" );
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
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "Edgehtml.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_in_range( version: fileVer, test_version: "11.0.10240.0", test_version2: "11.0.10240.18157" )){
	report = report_fixed_ver( file_checked: dllPath + "\\Edgehtml.dll", file_version: fileVer, vulnerable_range: "11.0.10240.0 - 11.0.10240.18157" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

