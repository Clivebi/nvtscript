CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107019" );
	script_version( "2021-10-04T14:22:38+0000" );
	script_cve_id( "CVE-2018-16514" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-21 16:12:00 +0000 (Fri, 21 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-22 11:26:28 +0200 (Sat, 22 Jun 2019)" );
	script_name( "MantisBT 'View Filters' And 'Edit Filter' Pages XSS Vulnerability (Jun 2019)" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site-scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to:

  - An input validation error for PATH_INFO in the View Filters page
    (view_filters_page.php).

  - An input validation error in the Edit Filter page(manage_filter_edit_page.php)." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary code (if CSP settings permit it) through a crafted PATH_INFO.

  NOTE: This vulnerability exists because of an incomplete fix for CVE-2018-13055." );
	script_tag( name: "affected", value: "MantisBT version 2.1.0 through 2.17.0." );
	script_tag( name: "solution", value: "Update to version 2.17.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=24731" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_in_range( version: version, test_version: "2.1.0", test_version2: "2.17.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.17.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

