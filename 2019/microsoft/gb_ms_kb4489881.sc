if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814937" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-0601", "CVE-2019-0603", "CVE-2019-0609", "CVE-2019-0614", "CVE-2019-0617", "CVE-2019-0665", "CVE-2019-0666", "CVE-2019-0667", "CVE-2019-0680", "CVE-2019-0690", "CVE-2019-0702", "CVE-2019-0703", "CVE-2019-0704", "CVE-2019-0746", "CVE-2019-0754", "CVE-2019-0755", "CVE-2019-0756", "CVE-2019-0759", "CVE-2019-0761", "CVE-2019-0762", "CVE-2019-0763", "CVE-2019-0765", "CVE-2019-0767", "CVE-2019-0772", "CVE-2019-0774", "CVE-2019-0775", "CVE-2019-0780", "CVE-2019-0782", "CVE-2019-0783", "CVE-2019-0784", "CVE-2019-0797", "CVE-2019-0821" );
	script_bugtraq_id( 107285 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-13 10:32:00 +0530 (Wed, 13 Mar 2019)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4489881)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4489881" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist,

  - When users to receive 'Error 1309' while installing or uninstalling
    certain types of MSI and MSP files.

  - With a virtual memory leak and the depletion of the paged pool with
    the CMNB tag that cause the server to become unresponsive.

  - In Internet Explorer, Windows App Platform and Frameworks, Windows Hyper-V,
    Windows Storage and Filesystems, Windows Fundamentals, Windows Kernel,
    Windows Server, Windows MSXML, and the Microsoft JET Database Engine.

  Please see the references for more information about the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to elevate privileges, execute arbitrary code, read unauthorized
  information, bypass security features and cause denial of service." );
	script_tag( name: "affected", value: "- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4489881" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "Msi.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "5.0.9600.19304" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Msi.dll", file_version: fileVer, vulnerable_range: "Less than 5.0.9600.19304" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

