CPE = "cpe:/a:theforeman:foreman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140490" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-07 10:56:49 +0700 (Tue, 07 Nov 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-17 10:29:00 +0000 (Wed, 17 Oct 2018)" );
	script_cve_id( "CVE-2017-15100" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Foreman XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foreman_detect.sc" );
	script_mandatory_keys( "foreman/installed" );
	script_tag( name: "summary", value: "Foreman is prone to a cross-site scripting vulnerability." );
	script_tag( name: "insight", value: "Facts reported by hosts to Foreman containing HTML are not properly escaped
on fact charts in the facts page, statistics page, and trends page when hovering over the chart with the mouse." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Foreman 1.2 and before 1.16.0." );
	script_tag( name: "solution", value: "Update to version 1.16.0 or later." );
	script_xref( name: "URL", value: "http://projects.theforeman.org/issues/21519" );
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
if(version_is_greater_equal( version: version, test_version: "1.2" ) && version_is_less( version: version, test_version: "1.16.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.16.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

