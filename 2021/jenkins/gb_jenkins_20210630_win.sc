CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146202" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-01 06:26:35 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-06 14:01:00 +0000 (Tue, 06 Jul 2021)" );
	script_cve_id( "CVE-2021-21670", "CVE-2021-21671" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Jenkins < 2.289.2, < 2.300 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Jenkins is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-21670: Improper permission checks allow canceling queue items and aborting builds

  - CVE-2021-21671: Session fixation" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to:

  - cancel queue items and abort builds of jobs for which they have Item/Cancel permission even
  when they do not have Item/Read permission.

  - use social engineering techniques to gain administrator access to Jenkins" );
	script_tag( name: "affected", value: "Jenkins version 2.299 and prior and 2.289.1 LTS and prior." );
	script_tag( name: "solution", value: "Update to version 2.300, 2.289.2 LTS or later." );
	script_xref( name: "URL", value: "https://www.jenkins.io/security/advisory/2021-06-30/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
proto = infos["proto"];
if( get_kb_item( "jenkins/" + port + "/is_lts" ) ){
	if(version_is_less( version: version, test_version: "2.289.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.289.2", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: version, test_version: "2.300" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.300", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

