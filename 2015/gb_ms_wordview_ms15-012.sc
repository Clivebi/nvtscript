if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805045" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-0064" );
	script_bugtraq_id( 72463 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-02-11 10:57:38 +0530 (Wed, 11 Feb 2015)" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerability (3032328)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-012." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A remote code execution vulnerability
  exists in Microsoft Word Viewer that is caused when Word improperly handles
  objects in memory while parsing specially crafted Office files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Office Word Viewer 2007 SP3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3032328" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2956092" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms15-012" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(wordviewVer){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8414" )){
		report = report_fixed_ver( installed_version: wordviewVer, vulnerable_range: "11.0 - 11.0.8414" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

