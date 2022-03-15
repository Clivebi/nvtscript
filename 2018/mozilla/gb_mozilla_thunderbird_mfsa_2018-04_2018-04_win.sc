CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813049" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5117", "CVE-2018-5089" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-22 11:44:40 +0530 (Thu, 22 Mar 2018)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2018-04_2018-04)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An integer overflow error in Skia library during edge builder allocation.

  - An use-after-free error while editing form elements.

  - An use-after-free error when source document is manipulated during XSLT.

  - An use-after-free error while manipulating form input elements.

  - An use-after-free error with widget listener.

  - An use-after-free error when manipulating HTML media elements.

  - An use-after-free error during mouse event handling.

  - An use-after-free error during font face manipulation.

  - An url spoofing with right-to-left text aligned left-to-right.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to bypass security restrictions and perform unauthorized
   actions, conduct spoofing attack, and execute arbitrary code in the
  context of the affected application." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 52.6 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 52.6
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-04/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
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
if(version_is_less( version: vers, test_version: "52.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "52.6", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

