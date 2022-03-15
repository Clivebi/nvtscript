if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813078" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-0870", "CVE-2018-0887", "CVE-2018-8116", "CVE-2018-0956", "CVE-2018-0957", "CVE-2018-0960", "CVE-2018-0966", "CVE-2018-0967", "CVE-2018-0968", "CVE-2018-0969", "CVE-2018-0970", "CVE-2018-0971", "CVE-2018-0972", "CVE-2018-0973", "CVE-2018-0974", "CVE-2018-0975", "CVE-2018-0976", "CVE-2018-0979", "CVE-2018-0980", "CVE-2018-0981", "CVE-2018-0987", "CVE-2018-0988", "CVE-2018-0989", "CVE-2018-0990", "CVE-2018-0991", "CVE-2018-0993", "CVE-2018-0994", "CVE-2018-0995", "CVE-2018-0996", "CVE-2018-0997", "CVE-2018-1000", "CVE-2018-1001", "CVE-2018-1009", "CVE-2018-1010", "CVE-2018-1012", "CVE-2018-1013", "CVE-2018-1015", "CVE-2018-1016", "CVE-2018-1018", "CVE-2018-1020", "CVE-2018-1023", "CVE-2018-1003", "CVE-2018-1004", "CVE-2018-1008" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-04-11 10:29:16 +0530 (Wed, 11 Apr 2018)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4093111)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4093111" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Windows font library improperly handles specially crafted embedded fonts.

  - Internet Explorer improperly accesses objects in memory.

  - Windows kernel fails to properly initialize a memory address.

  - Scripting engine does not properly handle objects in memory in Internet Explorer.

  - An error in Windows Adobe Type Manager Font Driver (ATMFD).

  - Scripting engine handles objects in memory in Internet Explorer.

  - Chakra scripting engine handles objects in memory in Microsoft Edge.

  - A Kernel Address Space Layout Randomization (ASLR) bypass error in windows.

  - Windows SNMP Service improperly handles malformed SNMP traps.

  - A security feature bypass exists when Device Guard incorrectly validates an
    untrusted file.

  - Microsoft browsers improperly access objects in memory.

  - Windows kernel improperly handles objects in memory.

  - VBScript engine improperly handles objects in memory.

  - An error in  Remote Desktop Protocol (RDP).

  - An error in HTTP 2.

  - Windows Hyper-V on a host operating system fails to properly validate
    input from an authenticated user on a guest operating system.

  - An error in the Microsoft JET Database Engine." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct arbitrary code execution, disclose sensitive information, escalate
  privileges, bypass security and cause denial of service condition." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4093111" );
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
if(version_in_range( version: edgeVer, test_version: "11.0.10240.0", test_version2: "11.0.10240.17830" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Edgehtml.dll", file_version: edgeVer, vulnerable_range: "11.0.10240.0 - 11.0.10240.17830" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

