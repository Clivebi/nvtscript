CPE = "cpe:/a:atlassian:jira";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106761" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-18 11:43:10 +0200 (Tue, 18 Apr 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-16 02:29:00 +0000 (Fri, 16 Feb 2018)" );
	script_cve_id( "CVE-2016-4318", "CVE-2016-4319" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Atlassian JIRA Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_atlassian_jira_detect.sc" );
	script_mandatory_keys( "atlassian_jira/installed" );
	script_tag( name: "summary", value: "Atlassian JIRA is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Atlassian JIRA is prone to multiple vulnerabilities:

  - XSS vulnerability in project/ViewDefaultProjectRoleActors.jspa via a role name. (CVE-2016-4318)

  - CSRF vulnerability in /auditing/settings. (CVE-2016-4319)" );
	script_tag( name: "affected", value: "Atlassian JIRA before 7.1.9." );
	script_tag( name: "solution", value: "Update to version 7.1.9 or later." );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/JRASERVER-61861" );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/JRASERVER-61803" );
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
if(version_is_less( version: version, test_version: "7.1.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.9" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

