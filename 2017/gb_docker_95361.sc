CPE = "cpe:/a:docker:docker";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140120" );
	script_bugtraq_id( 95361 );
	script_cve_id( "CVE-2016-9962" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-11 17:15:30 +0100 (Wed, 11 Jan 2017)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:01:00 +0000 (Tue, 09 Oct 2018)" );
	script_name( "Docker < 1.12.6 Local Privilege Escalation Vulnerability" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Privilege escalation" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_docker_http_rest_api_detect.sc", "gb_docker_ssh_login_detect.sc" );
	script_mandatory_keys( "docker/version" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/95361" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Jan/21" );
	script_tag( name: "summary", value: "Docker is prone to a local privilege escalation vulnerability." );
	script_tag( name: "impact", value: "A local attacker can exploit this issue to gain elevated
  privileges." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 1.12.6 or later." );
	script_tag( name: "affected", value: "Versions prior to Docker 1.12.6 are vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.12.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12.6" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

