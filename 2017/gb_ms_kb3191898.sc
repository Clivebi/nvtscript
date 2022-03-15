if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810795" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_cve_id( "CVE-2017-8507", "CVE-2017-8508" );
	script_bugtraq_id( 98827, 98828 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-15 13:43:00 +0000 (Fri, 15 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 13:22:44 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Outlook 2007 Service Pack 3 Multiple Vulnerabilities (KB3191898)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3191898" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A remote code execution vulnerability exists in the way that Microsoft
  Outlook parses specially crafted email messages.

  - A security feature bypass vulnerability exists in Microsoft Office software
  when it improperly handles the parsing of file formats." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to take control of an affected system." );
	script_tag( name: "affected", value: "Microsoft Outlook 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191898" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!outlookVer || !IsMatchRegexp( outlookVer, "^12\\." )){
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
if(version_in_range( version: outlookVer, test_version: "12.0", test_version2: "12.0.6770.4999" )){
	report = "File checked:     " + outlookFile + "outlook.exe" + "\n" + "File version:     " + outlookVer + "\n" + "Vulnerable range:  12.0 - 12.0.6770.4999" + "\n";
	security_message( data: report );
	exit( 0 );
}

