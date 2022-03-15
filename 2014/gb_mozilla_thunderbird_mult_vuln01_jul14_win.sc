CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804706" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1533", "CVE-2014-1538", "CVE-2014-1541" );
	script_bugtraq_id( 67965, 67976, 67979 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-07-04 10:04:28 +0530 (Fri, 04 Jul 2014)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities-01 July14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the 'RefreshDriverTimer::TickDriver' function in the SMIL
  Animation Controller.

  - An error in the 'nsTextEditRules::CreateMozBR' function.

  - An Unspecified error in the browser engine.

  - And some unspecified errors exist." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct clickjacking attacks
and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 24.6 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 24.6 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59171" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-48.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "24.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "24.6" );
	security_message( port: 0, data: report );
	exit( 0 );
}

