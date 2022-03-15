if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113455" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-12 13:46:35 +0000 (Mon, 12 Aug 2019)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-16 13:57:00 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-7616", "CVE-2019-10744" );
	script_name( "Elastic Kibana < 6.8.2, 7.x < 7.2.1 Multiple Vulnerabilities (ESA-2019-09, ESA-2019-10) (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_kibana_detect_http.sc", "os_detection.sc" );
	script_mandatory_keys( "elastic/kibana/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Kibana is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A server side request forgery (SSRF) flaw in the graphite integration for Timelion visualizer.
  An attacker with administrative Kibana access could set the timelion:graphite.url configuration
  option to an arbitrary URL. (CVE-2019-7616)

  - A prototype pollution flaw exists in lodash, a component used by KIbana. An attacker with access
  to Kibana may be able to use this lodash flaw to unexpectedly modify internal Kibana data. (CVE-2019-10744)" );
	script_tag( name: "impact", value: "- CVE-2019-7616: This could possibly lead to an attacker accessing external
  URL resources as the Kibana process on the host system. Successful exploitation would allow an attacker to
  read sensitive information.

  - CVE-2019-10744: Prototype pollution can be leveraged to execute a cross-site-scripting (XSS), denial of service
  (DoS), or Remote Code Execution attack against Kibana." );
	script_tag( name: "affected", value: "Kibana through version 6.8.1 and version 7.0.0 through 7.2.0." );
	script_tag( name: "solution", value: "Update to version 6.8.2 or 7.2.1 respectively." );
	script_xref( name: "URL", value: "https://discuss.elastic.co/t/elastic-stack-6-8-2-and-7-2-1-security-update/192963" );
	script_xref( name: "URL", value: "https://www.elastic.co/community/security/" );
	exit( 0 );
}
CPE = "cpe:/a:elastic:kibana";
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
if(version_is_less( version: version, test_version: "6.8.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.8.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

