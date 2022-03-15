CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817499" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9948", "CVE-2020-9951", "CVE-2020-9952", "CVE-2020-9983" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-23 22:15:00 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-09-22 17:43:15 +0530 (Tue, 22 Sep 2020)" );
	script_name( "Apple Safari Security Update (APPLE-SA-2020-09-16-3)" );
	script_tag( name: "summary", value: "Apple Safari is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion issue related to improper memory handling,

  - A use after free issue related to improper memory management,

  - An input validation issue,

  - An out-of-bounds write issue related to improper bounds checking." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct cross site scripting attacks and arbitrary code execution." );
	script_tag( name: "affected", value: "Apple Safari versions before 14.0" );
	script_tag( name: "solution", value: "Update to Apple Safari 14.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2020/Sep/38" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "14.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "14.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

