CPE = "cpe:/a:tibco:jasperreports_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140528" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-23 11:58:55 +0700 (Thu, 23 Nov 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-5533" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TIBCO JasperReports Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jasperreports_detect.sc" );
	script_mandatory_keys( "jasperreports/installed" );
	script_tag( name: "summary", value: "TIBCO JasperReports contain a vulnerability which fails to prevent remote
access to all the contents of the web application, including key configuration files." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "The impact includes the possible access to web application configuration
files that contain the credentials used by the server. Those credentials could then be used to affect external
systems accessed by the JasperReports Server." );
	script_tag( name: "affected", value: "TIBCO JasperReports Server version 6.4.0." );
	script_tag( name: "solution", value: "Update to version 6.4.2 or later." );
	script_xref( name: "URL", value: "https://www.tibco.com/support/advisories/2017/11/tibco-security-advisory-november-15-2017-tibco-jasperreports-server-2017" );
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
if(version_is_equal( version: version, test_version: "6.4.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

