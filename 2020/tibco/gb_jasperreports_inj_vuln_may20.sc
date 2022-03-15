CPE = "cpe:/a:tibco:jasperreports_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144000" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-28 05:27:10 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_cve_id( "CVE-2020-9410" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "TIBCO JasperReports <= 7.1.1, 7.2.0, 7.5.0 HTML Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jasperreports_detect.sc" );
	script_mandatory_keys( "jasperreports/installed" );
	script_tag( name: "summary", value: "TIBCO JasperReports is prone to an HTML injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "JasperReorts contains a vulnerability that allows an attacker to exploit
  HTML injection to gain full control of a web interface containing the output of the report generator component
  with the privileges of any user that views the affected report(s). The attacker can exploit this vulnerability
  when other users view a maliciously generated report, where those reports use Fusion Charts and a data source
  with contents controlled by the attacker." );
	script_tag( name: "impact", value: "An attacker could gain full control of the web interface displaying a
  generated report. Since the TIBCO JasperReports Library is used to generate reports as a component of web
  interfaces, the theoretical impact of this vulnerability is that the attacker can obtain the privileges of the
  highest privileged owner that views a maliciously generated report." );
	script_tag( name: "affected", value: "TIBCO JasperReports Server 7.1.1 and prior, 7.2.0 and 7.5.0." );
	script_tag( name: "solution", value: "Update to version 7.1.3, 7.2.2, 7.5.1 or later." );
	script_xref( name: "URL", value: "https://www.tibco.com/support/advisories/2020/05/tibco-security-advisory-may-19-2020-tibco-jasperreports-library" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "7.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "7.2.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "7.5.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.5.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

