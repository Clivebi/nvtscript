if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814163" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_cve_id( "CVE-2018-8522", "CVE-2018-8524", "CVE-2018-8576", "CVE-2018-8582" );
	script_bugtraq_id( 105820, 105823, 105822, 105825 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-14 12:58:38 +0530 (Wed, 14 Nov 2018)" );
	script_name( "Microsoft Outlook 2013 Service Pack 1 Multiple Vulnerabilities (KB4461486)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4461486." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist in,

  - The way that Microsoft Outlook parses specially modified rule export files.

  - Microsoft Outlook software when it fails to properly handle objects in
    memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to take control of an affected system and use a specially crafted
  file to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Outlook 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4461486" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/Office/Outlook/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
outlookVer = get_kb_item( "SMB/Office/Outlook/Version" );
if(!outlookVer || !IsMatchRegexp( outlookVer, "^15\\." )){
	exit( 0 );
}
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(!outlookFile){
	exit( 0 );
}
outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "outlook.exe" );
if(!outlookVer){
	exit( 0 );
}
if(version_in_range( version: outlookVer, test_version: "15.0", test_version2: "15.0.5085.0999" )){
	report = report_fixed_ver( file_checked: outlookFile + "\\outlook.exe", file_version: outlookVer, vulnerable_range: "15.0 - 15.0.5075.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

