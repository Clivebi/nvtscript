if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805055" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-0085", "CVE-2015-0086", "CVE-2015-0097" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-03-11 13:15:55 +0530 (Wed, 11 Mar 2015)" );
	script_name( "Microsoft Office Excel Viewer Remote Code Execution Vulnerabilities (3038999)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-022." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are exists when,

  - The Office software improperly handles objects in memory while parsing
    specially crafted Office files.

  - The Office software fails to properly handle rich text format files in
    memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Excel Viewer 2007 Service Pack 3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2956189" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms15-022" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/XLView/Version" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms15-022" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(IsMatchRegexp( excelviewVer, "^12\\..*" )){
	if(version_in_range( version: excelviewVer, test_version: "12.0", test_version2: "12.0.6717.4999" )){
		report = report_fixed_ver( installed_version: excelviewVer, vulnerable_range: "12.0 - 12.0.6717.4999" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

