CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809844" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-9899", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9900", "CVE-2016-9904", "CVE-2016-9905", "CVE-2016-9893" );
	script_bugtraq_id( 94885, 94884 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-12-29 11:39:06 +0530 (Thu, 29 Dec 2016)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2016-96_2016-96)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An Use-after-free while manipulating DOM events and audio elements.

  - A CSP bypass using marquee tag.

  - The Memory corruption in libGLES.

  - An Use-after-free in Editor while manipulating DOM subtrees.

  - A Restricted external resources can be loaded by SVG images through data URLs.

  - A Cross-origin information leak in shared atoms.

  - A Crash in EnumerateSubDocuments.

  - Other Memory Corruption Errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to steal cookie-based authentication credentials, bypass certain
  security restrictions, obtain sensitive information and execute arbitrary
  code in the context of the affected application. Failed exploit attempts
  will likely result in denial-of-service conditions." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 45.6 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird 45.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-96" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "45.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "45.6" );
	security_message( data: report );
	exit( 0 );
}

