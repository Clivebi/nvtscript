CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112780" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-16 09:25:11 +0000 (Thu, 16 Jul 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-21 16:41:00 +0000 (Tue, 21 Jul 2020)" );
	script_cve_id( "CVE-2020-2220", "CVE-2020-2221", "CVE-2020-2222", "CVE-2020-2223" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Jenkins < 2.245, < 2.235.2 LTS Multiple XSS Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Jenkins is prone to multiple cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Stored XSS vulnerability in job build time trend (CVE-2020-2220)

  - Stored XSS vulnerability in upstream cause (CVE-2020-2221)

  - Stored XSS vulnerability in 'keep forever' badge icons (CVE-2020-2222)

  - Stored XSS vulnerability in console links (CVE-2020-2223)" );
	script_tag( name: "affected", value: "Jenkins version 2.244 and prior and 2.235.1 LTS and prior." );
	script_tag( name: "solution", value: "Update to version 2.245, 2.235.2 LTS or later." );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2020-07-15/" );
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
	if(version_is_less( version: version, test_version: "2.235.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.235.2", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: version, test_version: "2.245" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.245", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

