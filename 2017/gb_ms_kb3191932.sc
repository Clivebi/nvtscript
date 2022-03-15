if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810796" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2017-8506", "CVE-2017-8507", "CVE-2017-8508" );
	script_bugtraq_id( 98811, 98827, 98828 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 13:29:30 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Outlook 2016 Multiple Vulnerabilities (KB3191932)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3191932" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A remote code execution vulnerability exists when Office,
  improperly validates input before loading dynamic link library
  (DLL) files.

  - A remote code execution vulnerability exists in the way that Microsoft
  Outlook parses  specially crafted email messages.

  - A security feature bypass vulnerability  exists in Microsoft Office
  software when it improperly handles the parsing of file formats." );
	script_tag( name: "impact", value: "Successful exploitation will allow to
  take control of an affected system and execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Outlook 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191932" );
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
if(!outlookVer || !IsMatchRegexp( outlookVer, "^16\\." )){
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
if(version_in_range( version: outlookVer, test_version: "16.0", test_version2: "16.0.4549.1001" )){
	report = "File checked:     " + outlookFile + "outlook.exe" + "\n" + "File version:     " + outlookVer + "\n" + "Vulnerable range:  16.0 - 16.0.4549.1001" + "\n";
	security_message( data: report );
	exit( 0 );
}

