if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811178" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-0193", "CVE-2017-8472", "CVE-2017-8473", "CVE-2017-8474", "CVE-2017-8527", "CVE-2017-8528", "CVE-2017-0282", "CVE-2017-8475", "CVE-2017-8476", "CVE-2017-8531", "CVE-2017-0283", "CVE-2017-0284", "CVE-2017-8477", "CVE-2017-8478", "CVE-2017-8479", "CVE-2017-8532", "CVE-2017-8533", "CVE-2017-0285", "CVE-2017-8480", "CVE-2017-8481", "CVE-2017-8543", "CVE-2017-0287", "CVE-2017-0288", "CVE-2017-8482", "CVE-2017-8483", "CVE-2017-8544", "CVE-2017-0289", "CVE-2017-0291", "CVE-2017-0292", "CVE-2017-8484", "CVE-2017-8485", "CVE-2017-8553", "CVE-2017-0294", "CVE-2017-0296", "CVE-2017-8488", "CVE-2017-8489", "CVE-2017-0297", "CVE-2017-0298", "CVE-2017-8490", "CVE-2017-8491", "CVE-2017-8492", "CVE-2017-0299", "CVE-2017-0300", "CVE-2017-8460", "CVE-2017-8462", "CVE-2017-8464", "CVE-2017-8470", "CVE-2017-8471", "CVE-2017-8469", "CVE-2017-8554" );
	script_bugtraq_id( 98878, 98851, 98852, 98902, 98933, 98949, 98885, 98853, 98903, 98819, 98920, 98918, 98854, 98845, 98856, 98820, 98821, 98914, 98857, 98862, 98824, 98922, 98923, 98858, 98859, 98826, 98929, 98835, 98836, 98847, 98860, 98940, 98837, 98839, 98864, 98865, 98840, 98867, 98869, 98870, 98884, 98901, 98887, 98900, 98818, 98848, 98849, 98842 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 17:00:32 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4022718)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4022718" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Users cannot print enhanced metafiles (EMF) or documents containing bitmaps
    rendered out of bounds using the BitMapSection(DIBSection) function.

  - Security updates to Microsoft Windows PDF, Windows shell, Windows Kernel,
    Microsoft Graphics Component, Microsoft Uniscribe and Windows Kernel-Mode
    Drivers." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to gain the same user rights as the current user. If the current user is
  logged on with administrative user rights, an attacker who successfully exploited the
  vulnerability could take control of an affected system. An attacker could then install
  programs, view, change, or delete data or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2012." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022718" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "win32k.sys" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.2.9200.22168" )){
	report = "File checked:     " + sysPath + "\\win32k.sys" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range:  Less than 6.2.9200.22168\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

