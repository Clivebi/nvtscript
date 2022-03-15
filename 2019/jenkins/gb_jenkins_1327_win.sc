CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142270" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-17 08:14:25 +0000 (Wed, 17 Apr 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 18:36:00 +0000 (Tue, 29 Sep 2020)" );
	script_cve_id( "CVE-2019-1003049", "CVE-2019-1003050" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Jenkins < 2.164.2 LTS and < 2.172 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Jenkins is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Jenkins is prone to multiple vulnerabilities:

  - Users who cached their CLI authentication would remain authenticated, because the fix for CVE-2019-1003004 does
    not reject existing remoting-based CLI authentication caches (CVE-2019-1003049)

  - The f:validateButton form control for the Jenkins UI does not properly escape job URLs, resulting in a
    cross-site scripting (XSS) vulnerability exploitable by users with the ability to control job names
    (CVE-2019-1003050)" );
	script_tag( name: "affected", value: "Jenkins LTS 2.164.1 and prior and Jenkins weekly 2.171 and prior." );
	script_tag( name: "solution", value: "Update to version 2.164.2 (LTS) and 2.172 (weekly)." );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2019-04-10/" );
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
	if(version_is_less( version: version, test_version: "2.164.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.164.2", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: version, test_version: "2.172" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.172", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

