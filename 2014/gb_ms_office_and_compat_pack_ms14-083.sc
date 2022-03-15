if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805024" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-6360", "CVE-2014-6361" );
	script_bugtraq_id( 71500, 71501 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-10 10:52:06 +0530 (Wed, 10 Dec 2014)" );
	script_name( "Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (3017347)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS14-083." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to:

  - An error related to a global free which can be exploited to corrupt memory.

  - An error related to an invalid pointer which can be exploited to corrupt
  memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3017347" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-083" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
cmpPckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(cmpPckVer && IsMatchRegexp( cmpPckVer, "^12\\." )){
	xlcnvVer = get_kb_item( "SMB/Office/XLCnv/Version" );
	if(xlcnvVer && IsMatchRegexp( xlcnvVer, "^12\\." )){
		if(version_in_range( version: xlcnvVer, test_version: "12.0", test_version2: "12.0.6713.4999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
