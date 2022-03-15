if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805183" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-1682", "CVE-2015-1683" );
	script_bugtraq_id( 74481, 74484 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-05-13 15:35:29 +0530 (Wed, 13 May 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Remote Code Execution Vulnerability (3057181)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-046." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as user supplied input is
  not properly validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Word 2010 Service Pack 2 and prior

  - Microsoft Word 2013 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2965237" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2965307" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-046" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
winwordVer = get_kb_item( "SMB/Office/Word/Version" );
if(winwordVer && IsMatchRegexp( winwordVer, "^(14|15).*" )){
	if(version_in_range( version: winwordVer, test_version: "14.0", test_version2: "14.0.7149.4999" ) || version_in_range( version: winwordVer, test_version: "15.0", test_version2: "15.0.4719.999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

