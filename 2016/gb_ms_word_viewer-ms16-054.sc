if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807822" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0198" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-05-11 12:57:51 +0530 (Wed, 11 May 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerability (3155544)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-054" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as office software fails
  to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word Viewer 2007." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115132" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3155544" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-054" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(wordviewVer){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8427" )){
		report = "File checked:     Wordview.exe " + "\n" + "File version:     " + wordviewVer + "\n" + "Vulnerable range: 11.0 - 11.0.8427 \n";
		security_message( data: report );
		exit( 0 );
	}
}

