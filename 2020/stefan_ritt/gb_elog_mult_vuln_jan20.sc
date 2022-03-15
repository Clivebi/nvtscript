if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113623" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-01-13 13:51:16 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-14 16:00:00 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-20375", "CVE-2019-20376" );
	script_name( "ELOG <= 3.1.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_elog_detect.sc" );
	script_mandatory_keys( "ELOG/detected" );
	script_tag( name: "summary", value: "ELOG is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A cross-site scripting (XSS) vulnerability allows remote attackers
    to inject arbitrary web script or HTML into the site via
    a crafted SVG document to elogd.c.

  - A cross-site scripting (XSS) vulnerability allows remote attackers
    to inject arbitrary web script or HTML into the site via
    the value parameter in a localization (loc) command to elogd.c." );
	script_tag( name: "affected", value: "ELOG through version 3.1.4." );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_xref( name: "URL", value: "https://bitbucket.org/ritt/elog/commits/eefdabb714f26192f585083ef96c8413e459a1d1" );
	script_xref( name: "URL", value: "https://bitbucket.org/ritt/elog/commits/993bed4923c88593cc6b1186e0d1b9564994a25a" );
	exit( 0 );
}
CPE = "cpe:/a:stefan_ritt:elog_web_logbook";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "3.1.4" ) || IsMatchRegexp( version, "^3.1.4($|\\.)" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Update to the latest version.", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

