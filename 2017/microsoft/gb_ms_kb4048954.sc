if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812089" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_cve_id( "CVE-2017-11839", "CVE-2017-11840", "CVE-2017-11841", "CVE-2017-11842", "CVE-2017-11843", "CVE-2017-11768", "CVE-2017-11873", "CVE-2017-11874", "CVE-2017-11880", "CVE-2017-11788", "CVE-2017-11791", "CVE-2017-11803", "CVE-2017-11827", "CVE-2017-11830", "CVE-2017-11831", "CVE-2017-11833", "CVE-2017-11834", "CVE-2017-11836", "CVE-2017-11837", "CVE-2017-11838", "CVE-2017-11844", "CVE-2017-11845", "CVE-2017-11846", "CVE-2017-11847", "CVE-2017-11848", "CVE-2017-11849", "CVE-2017-11850", "CVE-2017-11851", "CVE-2017-11853", "CVE-2017-11855", "CVE-2017-11856", "CVE-2017-11858", "CVE-2017-11861", "CVE-2017-11863", "CVE-2017-11866", "CVE-2017-11869", "CVE-2017-11870", "CVE-2017-11871", "CVE-2017-11872" );
	script_bugtraq_id( 101735, 101734, 101719, 101740, 101705, 101728, 101750, 101755, 101711, 101715, 101704, 101703, 101714, 101721, 101706, 101725, 101727, 101722, 101737, 101707, 101708, 101741, 101729, 101709, 101762, 101738, 101763, 101764, 101751, 101753, 101716, 101723, 101748, 101732, 101742, 101731, 101730, 101749 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-30 19:07:00 +0000 (Thu, 30 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-15 08:37:02 +0530 (Wed, 15 Nov 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4048954)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4048954" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when the Windows kernel fails to properly initialize a memory address.

  - A security feature bypass when Device Guard incorrectly validates an untrusted
    file.

  - An error in the way that Microsoft Edge handles cross-origin requests.

  - An error when the scripting engine does not properly handle objects in memory
    in Internet Explorer.

  - An error in the way the scripting engine handles objects in memory in Microsoft
    browsers.

  - An error in the way that the scripting engine handles objects in memory in
    Microsoft Edge.

  - An error when the Windows GDI component improperly discloses kernel memory
    addresses.

  - An error when Windows Search improperly handles objects in memory.

  - An error when the Windows kernel fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to potentially sensitive information, fake unsigned file appear
  to be signed, determine the origin of all web pages in the affected browser,
  gain the same user rights as the current user, cause a remote denial of service
  against a system, test for the presence of files on disk, force the browser to
  send data that would otherwise be restricted to a destination website of the
  attacker's choice and run arbitrary code in kernel mode." );
	script_tag( name: "affected", value: "Microsoft Windows 10 Version 1703 x32/x64." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4048954" );
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
if(version_in_range( version: edgeVer, test_version: "11.0.15063.0", test_version2: "11.0.15063.725" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Edgehtml.dll", file_version: edgeVer, vulnerable_range: "11.0.15063.0 - 11.0.15063.725" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

