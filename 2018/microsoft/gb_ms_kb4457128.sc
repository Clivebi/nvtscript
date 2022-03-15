if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814014" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8443", "CVE-2018-8445", "CVE-2018-8446", "CVE-2018-8447", "CVE-2018-8449", "CVE-2018-8452", "CVE-2018-0965", "CVE-2018-8271", "CVE-2018-8315", "CVE-2018-8332", "CVE-2018-8335", "CVE-2018-8354", "CVE-2018-8366", "CVE-2018-8367", "CVE-2018-8392", "CVE-2018-8393", "CVE-2018-8410", "CVE-2018-8419", "CVE-2018-8420", "CVE-2018-8421", "CVE-2018-8424", "CVE-2018-8425", "CVE-2018-8433", "CVE-2018-8434", "CVE-2018-8435", "CVE-2018-8436", "CVE-2018-8437", "CVE-2018-8438", "CVE-2018-8439", "CVE-2018-8440", "CVE-2018-8441", "CVE-2018-8442", "CVE-2018-8455", "CVE-2018-8456", "CVE-2018-8457", "CVE-2018-8459", "CVE-2018-8461", "CVE-2018-8462", "CVE-2018-8463", "CVE-2018-8464", "CVE-2018-8465", "CVE-2018-8466", "CVE-2018-8467", "CVE-2018-8468", "CVE-2018-8469", "CVE-2018-8470", "CVE-2018-8475", "CVE-2018-5391", "CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-05 15:46:00 +0000 (Mon, 05 Nov 2018)" );
	script_tag( name: "creation_date", value: "2018-09-12 12:17:54 +0530 (Wed, 12 Sep 2018)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4457128)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4457128" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Denial of service vulnerability (named 'FragmentSmack').

  - Hyper-V on a host server fails to properly validate guest operating system
    user input.

  - Windows bowser.sys kernel-mode driver fails to properly handle objects in
    memory.

  - Browser scripting engine improperly handle object types.

  - Windows font library improperly handles specially crafted embedded fonts.

  - SMB improperly handles specially crafted client requests.

  - Scripting engine improperly handles objects in memory.

  - Microsoft JET Database Engine improperly handles objects in memory.

  - Windows Kernel API improperly handles registry objects in memory.

  - Windows kernel fails to properly initialize a memory address.

  - MSXML parser improperly processes user input.

  - Microsoft .NET Framework improperly processes untrusted input.

  - Windows GDI component improperly discloses the contents of its memory.

  - Microsoft Edge improperly handles specific HTML content.

  - Windows Graphics component improperly handles objects in memory.

  - An integer overflow in Windows Subsystem for Linux.

  - Windows Hyper-V BIOS loader fails to provide a high-entropy source.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - Speculative execution side-channel vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to crash the affected system, execute arbitrary code on the host operating system,
  disclose contents of System memory and also read privileged data across trust
  boundaries." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4457128" );
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
if(version_in_range( version: edgeVer, test_version: "11.0.17134.0", test_version2: "11.0.17134.284" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Edgehtml.dll", file_version: edgeVer, vulnerable_range: "11.0.17134.0 - 11.0.17134.284" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );
