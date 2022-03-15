CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815730" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-11756", "CVE-2019-17008", "CVE-2019-13722", "CVE-2019-11745", "CVE-2019-17014", "CVE-2019-17009", "CVE-2019-17010", "CVE-2019-17005", "CVE-2019-17011", "CVE-2019-17012", "CVE-2019-17013" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-13 18:02:00 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-12-04 15:57:14 +0530 (Wed, 04 Dec 2019)" );
	script_name( "Mozilla Firefox Security Updates (mfsa_2019-36_2019-37)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use-after-free issues in SFTKSession object, worker destruction,

  - A stack corruption issue due to incorrect number of arguments in WebRTC code.

  - An out of bounds write issue in NSS when encrypting with a block cipher.

  - Dragging and dropping of a cross-origin resource.

  - A use-after-free issue when performing device orientation checks and when
    retrieving a document in antitracking

  - A buffer overflow issue in plain text serializer.

  - Memory safety bugs." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code, gain access to sensitive information
  or conduct denial of service attacks." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 71 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 71
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2019-36/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "71" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "71", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

