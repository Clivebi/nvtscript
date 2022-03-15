CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808683" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-2807", "CVE-2016-2806", "CVE-2016-2804", "CVE-2016-2805" );
	script_bugtraq_id( 88100 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-07 11:35:44 +0530 (Wed, 07 Sep 2016)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2016-39_2016-48) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:
  multiple unspecified vulnerabilities in the browser engine." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Thunderbird versions before 45.1." );
	script_tag( name: "solution", value: "Update to version 45.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-39/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "45.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "45.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

