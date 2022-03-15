CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106642" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-13 14:33:08 +0700 (Mon, 13 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 00:35:00 +0000 (Tue, 19 Mar 2019)" );
	script_cve_id( "CVE-2017-6797" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT XSS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A cross-site scripting (XSS) vulnerability in bug_change_status_page.php
allows remote attackers to inject arbitrary JavaScript via the 'action_type' parameter." );
	script_tag( name: "affected", value: "MantisBT version prior 1.3.7 and 2.x before 2.2.1." );
	script_tag( name: "solution", value: "Update to MantisBT 1.3.7, 2.2.1 or later." );
	script_xref( name: "URL", value: "https://www.mantisbt.org/bugs/view.php?id=22486" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.3.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\." )){
	if(version_is_less( version: version, test_version: "2.2.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.2.1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

