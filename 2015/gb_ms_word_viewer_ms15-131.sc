if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806175" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-12-09 13:05:09 +0530 (Wed, 09 Dec 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerability (3116111)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-131." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to improper handling of files
  in the memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word Viewer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114479" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS15-131" );
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
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8421" )){
		report = "File checked:     Wordview.exe" + "\n" + "File version:     " + wordviewVer + "\n" + "Vulnerable range: 11.0 - 11.0.8421 \n";
		security_message( data: report );
		exit( 0 );
	}
}

