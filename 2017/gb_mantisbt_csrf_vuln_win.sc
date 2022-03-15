CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106831" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-23 10:37:27 +0700 (Tue, 23 May 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_cve_id( "CVE-2017-7620" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT CSRF Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "MantisBT is prone to a cross-site request forgery (CSRF) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "MantisBT omits a backslash check in string_api.php and consequently has
conflicting interpretations of an initial \\/ substring as introducing either a local pathname or a remote
hostname, which leads to arbitrary Permalink Injection via CSRF attacks on a permalink_page.php?url= URI and
an open redirect via a login_page.php?return= URI." );
	script_tag( name: "affected", value: "MantisBT version prior 1.3.11, 2.x before 2.3.3 and 2.4.x before 2.4.1." );
	script_tag( name: "solution", value: "Update to MantisBT 1.3.11, 2.3.3, 2.4.1 or later." );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=22702" );
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
if(version_is_less( version: version, test_version: "1.3.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2\\." )){
	if(version_is_less( version: version, test_version: "2.3.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.3.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( version, "^2\\.4\\." ) && version_is_less( version: version, test_version: "2.4.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.4.1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

