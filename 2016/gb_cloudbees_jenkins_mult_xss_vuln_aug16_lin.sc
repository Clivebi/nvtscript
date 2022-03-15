CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808274" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_cve_id( "CVE-2012-0324", "CVE-2012-0325" );
	script_bugtraq_id( 52384 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-08-04 13:00:04 +0530 (Thu, 04 Aug 2016)" );
	script_name( "Jenkins Multiple Cross Site Scripting Vulnerabilities (Mar 2012) - Linux" );
	script_tag( name: "summary", value: "This host is installed with Jenkins and is prone
  to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple input validation errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject malicious HTMLs to pages served by Jenkins. This allows
  an attacker to escalate his privileges by hijacking sessions of other users." );
	script_tag( name: "affected", value: "Jenkins main line 1.452 and prior, Jenkins LTS 1.424.3 and prior." );
	script_tag( name: "solution", value: "Jenkins main line users should update to 1.454,
  Jenkins LTS users should update to 1.424.6." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2012-03-05/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "jenkins/detected", "Host/runs_unixoide" );
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
	if(version_is_less( version: version, test_version: "1.424.6" )){
		vuln = TRUE;
		fix = "1.424.6";
	}
}
else {
	if(version_is_less( version: version, test_version: "1.454" )){
		vuln = TRUE;
		fix = "1.454";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

