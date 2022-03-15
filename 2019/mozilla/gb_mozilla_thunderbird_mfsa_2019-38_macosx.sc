CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815859" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2019-17008", "CVE-2019-17011", "CVE-2019-11745", "CVE-2019-17012", "CVE-2019-17010", "CVE-2019-17005" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-16 19:15:00 +0000 (Thu, 16 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-12-06 12:30:55 +0530 (Fri, 06 Dec 2019)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2019-38)-Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An use after free error when retrieving a document in antitracking.

  - A buffer overflow error in plain text serializer.

  - An use-after-free error when performing device orientation checks.

  - An out of bounds write error in NSS when encrypting with a block cipher.

  - An use-after-free error in worker destruction." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  run arbitrary code and crash the affected system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 68.3 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 68.3
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-38/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "68.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "68.3", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

