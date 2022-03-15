if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810685" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_cve_id( "CVE-2017-0194" );
	script_bugtraq_id( 97436 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-04-12 09:03:42 +0530 (Wed, 12 Apr 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Excel Information Disclosure Vulnerability (KB3191827)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office Excel according to Microsoft security update KB3191827." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as Microsoft Office improperly
  discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and use the
  information to compromise the user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Excel 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191827" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
if(!excelVer){
	exit( 0 );
}
excelPath = get_kb_item( "SMB/Office/Excel/Install/Path" );
if(!excelPath){
	excelPath = "Unable to fetch the install path";
}
if(( IsMatchRegexp( excelVer, "^12\\." ) ) && version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6766.4999" )){
	report = "File checked:     " + excelPath + "Excel.exe" + "\n" + "File version:     " + excelVer + "\n" + "Vulnerable range: " + "12.0 - 12.0.6766.4999" + "\n";
	security_message( data: report );
	exit( 0 );
}

