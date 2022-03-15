if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805026" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-6356", "CVE-2014-6357" );
	script_bugtraq_id( 71469, 71470 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-10 12:31:36 +0530 (Wed, 10 Dec 2014)" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerabilities (3017301)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS14-081." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to:

  - An invalid indexing error when parsing Office files can be exploited to
    execute arbitrary code via a specially crafted Office file.

  - A use-after-free error when parsing Office files can be exploited to execute
    arbitrary code via a specially crafted Office file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute the arbitrary code, cause memory corruption and
  compromise the system." );
	script_tag( name: "affected", value: "Microsoft Office Word Viewer 2007 SP3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3017301" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-081" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(wordviewVer){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8413" )){
		report = report_fixed_ver( installed_version: wordviewVer, vulnerable_range: "11.0 - 11.0.8413" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

