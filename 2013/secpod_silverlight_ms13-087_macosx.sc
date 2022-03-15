CPE = "cpe:/a:microsoft:silverlight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901224" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3896" );
	script_bugtraq_id( 62793 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-10-09 12:56:06 +0530 (Wed, 09 Oct 2013)" );
	script_name( "Microsoft Silverlight Information Disclosure Vulnerability-2890788 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-087." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Download and install the hotfixes from the referenced advisory." );
	script_tag( name: "insight", value: "Flaw is caused when Silverlight improperly handles certain objects in
  memory." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5 on Mac OS X." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2890788" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-087" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_ms_silverlight_detect_macosx.sc" );
	script_mandatory_keys( "MS/Silverlight/MacOSX/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!msl_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( msl_ver, "^5\\." )){
	if(version_in_range( version: msl_ver, test_version: "5.0", test_version2: "5.1.20912.0" )){
		report = report_fixed_ver( installed_version: msl_ver, vulnerable_range: "5.0 - 5.1.20912.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

