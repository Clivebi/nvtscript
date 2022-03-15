if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810911" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2017-8509", "CVE-2017-8511" );
	script_bugtraq_id( 98812, 98815 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 10:12:53 +0530 (Wed, 14 Jun 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Remote Code Execution Vulnerabilities-KB3212223 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft security update KB3212223." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple errors when
  the software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3212223" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!offVer = get_kb_item( "MS/Office/MacOSX/Ver" )){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^(14\\.)" ) && version_in_range( version: offVer, test_version: "14.1.0", test_version2: "14.7.4" )){
	report = "File version:     " + offVer + "\n" + "Vulnerable range: 14.1.0 - 14.7.4" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

