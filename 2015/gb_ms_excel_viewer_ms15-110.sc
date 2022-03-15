if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806122" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-2558" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-14 10:49:22 +0530 (Wed, 14 Oct 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Excel Viewer Remote Code Execution Vulnerabilities (3096440)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-110." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when,

  - Microsoft Excel improperly handles the loading of dynamic link library
    (DLL) files.

  - Error when memory is released in an unintended manner.

  - Improper handling of files in the memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to execute remote code." );
	script_tag( name: "affected", value: "Microsoft Excel Viewer 2007 Service Pack 3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3096440" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085619" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS15-110" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/XLView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(IsMatchRegexp( excelviewVer, "^12\\..*" )){
	if(version_in_range( version: excelviewVer, test_version: "12.0", test_version2: "12.0.6732.4999" )){
		report = "File checked:  Xlview.exe" + "\n" + "File version:     " + excelviewVer + "\n" + "Vulnerable range: 12 - 12.0.6732.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

