if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807081" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0054" );
	script_bugtraq_id( 82508, 82652, 82654 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-03-01 14:45:35 +0530 (Tue, 01 Mar 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities-3134226(Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-015" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory
  corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers  to execute arbitrary code in the context of the currently
  logged-in user. Failed exploit attempts will likely result in denial of
  service conditions." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3137721" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-015" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
offVer = get_kb_item( "MS/Office/MacOSX/Ver" );
if(offVer && IsMatchRegexp( offVer, "^(14\\.1)" )){
	if(version_is_less( version: offVer, test_version: "14.6.1" )){
		report = "File version:     " + offVer + "\n" + "Vulnerable range: 14.1.0 - 14.6.0 " + "\n";
		security_message( data: report );
	}
}
exit( 99 );

