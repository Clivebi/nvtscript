CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815213" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-11703", "CVE-2019-11704", "CVE-2019-11705", "CVE-2019-11706" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-16 20:15:00 +0000 (Fri, 16 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-06-14 17:48:58 +0530 (Fri, 14 Jun 2019)" );
	script_name( "Mozilla Thunderbird Security Updates (mfsa_2019-16_2019-17)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple heap buffer overflow issues in icalparser.c and icalvalue.c.

  - A stack buffer overflow issue in icalrecur.c.

  - A type confusion issue in icalproperty.c." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers
  to crash the application." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 60.7.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird 60.7.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-17/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "60.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "60.7.1", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

