CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807013" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-3661", "CVE-2014-3662", "CVE-2014-3663", "CVE-2014-3664", "CVE-2014-3680", "CVE-2014-3681", "CVE-2014-3666", "CVE-2014-3667", "CVE-2013-2186", "CVE-2014-1869" );
	script_bugtraq_id( 77953, 77963, 88193, 77977, 77955, 77961 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-12-21 15:34:06 +0530 (Mon, 21 Dec 2015)" );
	script_name( "Jenkins Multiple Vulnerabilities (Oct 2014) - Windows" );
	script_tag( name: "summary", value: "This host is installed with
  Jenkins and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Jenkins does not properly prevent downloading of plugins.

  - Insufficient sanitization of packets over the CLI channel.

  - Password exposure in DOM.

  - Error in job configuration permission.

  - Thread exhaustion via vectors related to a CLI handshake." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information, to bypass bypass intended access
  restrictions and execute arbitrary code." );
	script_tag( name: "affected", value: "Jenkins main line 1.582 and prior, Jenkins LTS 1.565.2 and prior." );
	script_tag( name: "solution", value: "Jenkins main line users should update to 1.583,
  Jenkins LTS users should update to 1.565.3." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2014-10-01/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_windows" );
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
	if(version_is_less( version: version, test_version: "1.565.3" )){
		vuln = TRUE;
		fix = "1.565.3";
	}
}
else {
	if(version_is_less( version: version, test_version: "1.583" )){
		vuln = TRUE;
		fix = "1.583";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

