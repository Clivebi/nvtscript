CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814048" );
	script_version( "2021-07-01T02:00:36+0000" );
	script_cve_id( "CVE-2018-12385" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 19:03:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-09-25 11:34:36 +0530 (Tue, 25 Sep 2018)" );
	script_name( "Mozilla Firefox ESR Security Updates(mfsa_2018-22_2018-23)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to data stored in the
  local cache in the user profile directory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to write data into the local cache or from locally installed malware. This issue
  also triggers a non-exploitable startup crash for users." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 60.2.1
  on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 60.2.1
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2018-23" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "60.2.1" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "60.2.1", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}

