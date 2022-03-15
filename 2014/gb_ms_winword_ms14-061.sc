if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804495" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_cve_id( "CVE-2014-4117" );
	script_bugtraq_id( 70360 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-10-15 11:05:58 +0530 (Wed, 15 Oct 2014)" );
	script_name( "Microsoft Office Word Remote Code Execution Vulnerability (3000434)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS14-061." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error when
  handling Microsoft Word files and can be exploited to execute arbitrary code
  via a specially crafted file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute the arbitrary code, cause memory corruption and
  compromise the system." );
	script_tag( name: "affected", value: "- Microsoft Word 2007 Service Pack 3 and prior

  - Microsoft Word 2010 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2883032" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2883013" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-061" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
winwordVer = get_kb_item( "SMB/Office/Word/Version" );
if(winwordVer && IsMatchRegexp( winwordVer, "^(12|14).*" )){
	if(version_in_range( version: winwordVer, test_version: "12.0", test_version2: "12.0.6705.4999" ) || version_in_range( version: winwordVer, test_version: "14.0", test_version2: "14.0.7134.4999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

