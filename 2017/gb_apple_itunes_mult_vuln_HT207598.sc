CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810725" );
	script_version( "2021-09-14T08:30:17+0000" );
	script_cve_id( "CVE-2009-3270", "CVE-2009-3560", "CVE-2009-3720", "CVE-2012-1147", "CVE-2012-1148", "CVE-2012-6702", "CVE-2013-7443", "CVE-2015-1283", "CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416", "CVE-2015-3717", "CVE-2015-6607", "CVE-2016-0718", "CVE-2016-4472", "CVE-2016-5300", "CVE-2016-6153" );
	script_bugtraq_id( 74228 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 08:30:17 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-03-30 17:45:29 +0530 (Thu, 30 Mar 2017)" );
	script_name( "Apple iTunes Multiple Vulnerabilities (HT207598) - Mac OS X" );
	script_tag( name: "summary", value: "Apple iTunes is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple issues in SQLite and expat." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code, cause unexpected application termination and disclose sensitive information." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.6." );
	script_tag( name: "solution", value: "Update to version 12.6.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207598" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_itunes_detect_macosx.sc" );
	script_mandatory_keys( "Apple/iTunes/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

