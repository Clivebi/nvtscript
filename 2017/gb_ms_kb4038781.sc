if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811757" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-0161", "CVE-2017-8719", "CVE-2017-8720", "CVE-2017-8723", "CVE-2017-8728", "CVE-2017-11766", "CVE-2017-8628", "CVE-2017-8643", "CVE-2017-8733", "CVE-2017-8734", "CVE-2017-8735", "CVE-2017-8736", "CVE-2017-8675", "CVE-2017-8676", "CVE-2017-8737", "CVE-2017-8738", "CVE-2017-8741", "CVE-2017-8677", "CVE-2017-8747", "CVE-2017-8748", "CVE-2017-8678", "CVE-2017-8679", "CVE-2017-8749", "CVE-2017-8750", "CVE-2017-8753", "CVE-2017-8681", "CVE-2017-8682", "CVE-2017-8754", "CVE-2017-8756", "CVE-2017-8757", "CVE-2017-8759", "CVE-2017-8683", "CVE-2017-8687", "CVE-2017-8688", "CVE-2017-8699", "CVE-2017-8702", "CVE-2017-8706", "CVE-2017-8707", "CVE-2017-8708", "CVE-2017-8709", "CVE-2017-8713", "CVE-2017-8692", "CVE-2017-8695" );
	script_bugtraq_id( 100728, 100768, 100739, 100729, 100744, 100747, 100737, 100738, 100740, 100743, 100752, 100755, 100749, 100759, 100764, 100767, 100765, 100766, 100769, 100720, 100770, 100771, 100776, 100727, 100772, 100779, 100718, 100721, 100742, 100781, 100736, 100756, 100783, 100785, 100789, 100790, 100791, 100792, 100796, 100762, 100773 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 19:58:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2017-09-13 16:02:14 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4038781)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4038781" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - When Windows Hyper-V on a host operating system fails to properly validate
    input from an authenticated user on a guest operating system.

  - An error in Windows Error Reporting (WER) when WER handles and executes files.

  - When the Windows kernel fails to properly initialize a memory address,
    allowing an attacker to retrieve information that could lead to a Kernel Address
    Space Layout Randomization (KASLR) bypass.

  - When the Windows kernel improperly handles objects in memory.

  - When Microsoft Edge improperly handles clipboard events.

  - An error in Microsoft's implementation of the Bluetooth stack.

  - An error in the way that Microsoft browser JavaScript engines render content when
    handling objects in memory.

  - When Microsoft Edge improperly accesses objects in memory.

  - An error due to the way Windows Uniscribe handles objects in memory.

  - When the Microsoft Windows Graphics Component improperly handles objects in
    memory.

  - When Microsoft browsers improperly access objects in memory.

  - An error in the way that the scripting engine handles objects in memory in
    Microsoft Edge.

  - A security feature bypass exists in Microsoft Edge when the Edge Content
    Security Policy (CSP) fails to properly validate certain specially crafted
    documents.

  - An error in the way Microsoft Edge handles objects in memory.

  - When Internet Explorer improperly handles specific HTML content.

  - When Microsoft Windows PDF Library improperly handles objects in memory.

  - An error in Microsoft browsers due to improper parent domain verification in
    certain functionality.

  - When Microsoft Edge does not properly parse HTTP content.

  - An error in the way that the Windows Graphics Device Interface (GDI) handles
    objects in memory, allowing an attacker to retrieve information from a targeted
    system.

  - When the Windows GDI+ component improperly discloses kernel memory addresses.

  - An error in Windows when the Windows kernel-mode driver fails to properly handle
    objects in memory.

  - An error in the way that the Windows Graphics Device Interface+ (GDI+) handles
    objects in memory, allowing an attacker to retrieve information from a targeted
    system.

  - An error when Windows Shell does not properly validate file copy destinations.

  - When Windows Uniscribe improperly discloses the contents of its memory.

  - An error in Windows kernel that could allow an attacker to retrieve information
    that could lead to a Kernel Address Space Layout Randomization (KASLR) bypass.

  - When Internet Explorer improperly accesses objects in memory.

  - When the Windows font library improperly handles specially crafted embedded
    fonts.

  - An error in Windows when the Win32k component fails to properly handle objects in
    memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  gain access to potentially sensitive information, perform a man-in-the-middle
  attack and force a user's computer to unknowingly route traffic through the
  attacker's computer, embed an ActiveX control, execute arbitrary code, take control
  of the affected system, gain the same user rights as the current user, conduct
  phishing attack and conduct redirect attacks." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4038781" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_in_range( version: edgeVer, test_version: "11.0.10240.0", test_version2: "11.0.10240.17608" )){
	report = "File checked:     " + sysPath + "\\Edgehtml.dll" + "\n" + "File version:     " + edgeVer + "\n" + "Vulnerable range: 11.0.10240.0 - 11.0.10240.17608\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

