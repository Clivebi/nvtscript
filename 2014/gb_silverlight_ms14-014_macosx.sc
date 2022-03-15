CPE = "cpe:/a:microsoft:silverlight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804408" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-0319" );
	script_bugtraq_id( 66046 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-03-12 08:10:37 +0530 (Wed, 12 Mar 2014)" );
	script_name( "Microsoft Silverlight Security Bypass Vulnerability (2932677) (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-014." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is caused when Silverlight improperly handles certain objects in
  memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain potentially
sensitive information." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5 on Mac OS X." );
	script_tag( name: "solution", value: "Download and install the hotfixes from the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2932677" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(version_in_range( version: msl_ver, test_version: "5.0", test_version2: "5.1.30213" )){
		report = report_fixed_ver( installed_version: msl_ver, vulnerable_range: "5.0 - 5.1.30213" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

