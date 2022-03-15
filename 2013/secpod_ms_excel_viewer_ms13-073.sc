if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902998" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159" );
	script_bugtraq_id( 62167, 62219, 62225 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 13:36:18 +0530 (Wed, 11 Sep 2013)" );
	script_name( "Microsoft Office Excel Viewer Remote Code Execution Vulnerabilities (2858300)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-073." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws exist when processing XML data, which can be exploited to
  disclose contents of certain local files by sending specially crafted XML data including external entity references." );
	script_tag( name: "affected", value: "Microsoft Office Excel Viewer 2007." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to corrupt memory and
  disclose sensitive information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2760590" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-073" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/XLView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(IsMatchRegexp( excelviewVer, "^12\\." )){
	if(version_in_range( version: excelviewVer, test_version: "12.0", test_version2: "12.0.6679.4999" )){
		report = report_fixed_ver( installed_version: excelviewVer, vulnerable_range: "12.0 - 12.0.6679.4999" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

