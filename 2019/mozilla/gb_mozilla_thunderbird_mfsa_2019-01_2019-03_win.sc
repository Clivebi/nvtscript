CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814667" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2018-18500", "CVE-2018-18505", "CVE-2018-18501", "CVE-2016-5824" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-02 07:29:00 +0000 (Tue, 02 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-01-30 13:07:16 +0530 (Wed, 30 Jan 2019)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2019-01_2019-03)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Memory safety bugs.

  - An use after free error via a crafted ics file.

  - Lack of message validation in the listener process for an Inter-process
    Communication.

  - An use after free error while parsing an HTML5 stream." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to cause denial of service condition, run arbitrary code and escalate privileges." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 60.5 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 60.5. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-03/" );
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
tbVer = infos["version"];
tbPath = infos["location"];
if(version_is_less( version: tbVer, test_version: "60.5" )){
	report = report_fixed_ver( installed_version: tbVer, fixed_version: "60.5", install_path: tbPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

