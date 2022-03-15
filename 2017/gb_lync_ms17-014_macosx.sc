CPE = "cpe:/a:microsoft:lync";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810817" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_cve_id( "CVE-2017-0129" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-20 12:56:16 +0530 (Mon, 20 Mar 2017)" );
	script_name( "Microsoft Lync Certificate Validation Vulnerability-4013241 (MAC OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS17-014." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when the Lync client fails
  to properly validate certificates." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to tamper the trusted communications between the server and target client." );
	script_tag( name: "affected", value: "Microsoft Lync version 2011 for MAC OS X." );
	script_tag( name: "solution", value: "Upgrade Microsoft Lync version 14.4.3.170308 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/4012487" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS17-014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_lync_detect_macosx.sc" );
	script_mandatory_keys( "Microsoft/Lync/MacOSX/Version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4012487" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!lyncVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( lyncVer, "(^14\\.)" )){
	;
}
{
	if(version_is_less( version: lyncVer, test_version: "14.4.3.170308" )){
		report = report_fixed_ver( installed_version: lyncVer, fixed_version: "14.4.3.170308" );
		security_message( data: report );
		exit( 0 );
	}
}

