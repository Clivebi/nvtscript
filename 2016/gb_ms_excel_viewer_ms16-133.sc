if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809721" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-7229", "CVE-2016-7231" );
	script_bugtraq_id( 93995, 93996 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-11-09 14:14:57 +0530 (Wed, 09 Nov 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Excel Viewer Multiple Remote Code Execution Vulnerabilities (3199168)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-133." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as Office software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in
  user." );
	script_tag( name: "affected", value: "Microsoft Excel Viewer 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3127893" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-133" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/XLView/Version", "SMB/Office/XLCnv/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(IsMatchRegexp( excelviewVer, "^12\\..*" )){
	if(version_in_range( version: excelviewVer, test_version: "12.0", test_version2: "12.0.6759.4999" )){
		report = "File checked:     Xlview.exe" + "\n" + "File version:     " + excelviewVer + "\n" + "Vulnerable range: 12 - 12.0.6759.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

