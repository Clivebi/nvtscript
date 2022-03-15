if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807858" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2016-3284", "CVE-2016-3279" );
	script_bugtraq_id( 91594, 91587 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-07-13 10:43:35 +0530 (Wed, 13 Jul 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Excel Multiple Vulnerabilities (3170008)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-088." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as office software
  improperly handles the parsing of file formats and office software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and run arbitrary code in
  the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Excel 2007 Service Pack 3 and prior

  - Microsoft Excel 2010 Service Pack 2 and prior

  - Microsoft Excel 2013 Service Pack 1 and prior

  - Microsoft Excel 2016 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115306" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115322" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115272" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115262" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3170008" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-088" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( excelVer, "^(12|14|15|16)\\..*" )){
	if( IsMatchRegexp( excelVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6750.4999";
	}
	else {
		if( IsMatchRegexp( excelVer, "^14" ) ){
			Vulnerable_range = "14 - 14.0.7171.4999";
		}
		else {
			if( IsMatchRegexp( excelVer, "^15" ) ){
				Vulnerable_range = "15 - 15.0.4841.0999";
			}
			else {
				if(IsMatchRegexp( excelVer, "^16" )){
					Vulnerable_range = "16 - 16.0.4405.999";
				}
			}
		}
	}
	if(version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6750.4999" ) || version_in_range( version: excelVer, test_version: "14.0", test_version2: "14.0.7171.4999" ) || version_in_range( version: excelVer, test_version: "15.0", test_version2: "15.0.4841.0999" ) || version_in_range( version: excelVer, test_version: "16.0", test_version2: "16.0.4405.999" )){
		report = "File checked:     " + excelPath + "Excel.exe" + "\n" + "File version:     " + excelVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

