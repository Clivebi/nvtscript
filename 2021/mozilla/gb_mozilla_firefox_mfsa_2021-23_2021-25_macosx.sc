CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818160" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_cve_id( "CVE-2021-29960", "CVE-2021-29961", "CVE-2021-29959", "CVE-2021-29967", "CVE-2021-29966" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-25 13:23:00 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-07-08 16:31:05 +0530 (Thu, 08 Jul 2021)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2021-23_2021-25) - MAC OS X" );
	script_tag( name: "summary", value: "The host is missing a security update
  according to Mozilla advisory" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Password Manager on Firefox for Android susceptible to domain spoofing.

  - Firefox UI spoof using 'select' elements and CSS scaling.

  - Devices could be re-enabled without additional permission prompt.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions and conduct
  spoofing attack." );
	script_tag( name: "affected", value: "Mozilla Firefox version before
  89 on MAC OS X." );
	script_tag( name: "solution", value: "Update Mozilla Firefox to version 89
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-23/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "89" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "89", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

