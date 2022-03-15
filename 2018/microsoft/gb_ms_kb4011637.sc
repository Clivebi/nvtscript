if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812705" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_cve_id( "CVE-2018-0791" );
	script_bugtraq_id( 102383 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-10 10:34:31 +0530 (Wed, 10 Jan 2018)" );
	script_name( "Microsoft Outlook 2013 Service Pack 1 Remote Code Execution Vulnerability (KB4011637)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011637" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the way that
  Microsoft Outlook parses specially crafted email messages." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker who successfully exploited the vulnerability to take control
  of an affected system. An attacker could then:

  - install programs

  - view, change, or delete data

  - or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Outlook 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011637" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Outlook/Version" );
	script_require_ports( 139, 445 );
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
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(!outlookFile){
	exit( 0 );
}
outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "outlook.exe" );
if(!outlookVer){
	exit( 0 );
}
if(version_in_range( version: outlookVer, test_version: "15.0", test_version2: "15.0.4997.0999" )){
	report = report_fixed_ver( file_checked: outlookFile + "outlook.exe", file_version: outlookVer, vulnerable_range: "15.0 - 15.0.4997.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );
