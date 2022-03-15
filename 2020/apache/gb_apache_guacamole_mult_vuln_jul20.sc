CPE = "cpe:/a:apache:guacamole";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144236" );
	script_version( "2021-07-22T02:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-15 04:25:21 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-29 19:38:00 +0000 (Mon, 29 Mar 2021)" );
	script_cve_id( "CVE-2020-9497", "CVE-2020-9498" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Guacamole < 1.2.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apache_guacamole_http_detect.sc" );
	script_mandatory_keys( "apache/guacamole/detected" );
	script_tag( name: "summary", value: "Apache Guacamole is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Improper input validation of RDP static virtual channels (CVE-2020-9497)

  - Dangling pointer in RDP static virtual channel handling (CVE-2020-9498)" );
	script_tag( name: "affected", value: "Apache Guacamole version 1.1.0 and prior." );
	script_tag( name: "solution", value: "Update to version 1.2.0 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r3f071de70ea1facd3601e0fa894e6cadc960627ee7199437b5a56f7f@%3Cannounce.apache.org%3E" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r26fb170edebff842c74aacdb1333c1338f0e19e5ec7854d72e4680fc@%3Cannounce.apache.org%3E" );
	script_xref( name: "URL", value: "https://research.checkpoint.com/2020/apache-guacamole-rce/" );
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
if(version_is_less( version: version, test_version: "1.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

