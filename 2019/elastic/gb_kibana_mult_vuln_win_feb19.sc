if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112542" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-27 11:58:11 +0100 (Wed, 27 Mar 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-19 18:09:00 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-7608", "CVE-2019-7609", "CVE-2019-7610" );
	script_name( "Elastic Kibana < 5.6.15, 6.x.x < 6.6.1 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_kibana_detect_http.sc", "os_detection.sc" );
	script_mandatory_keys( "elastic/kibana/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Kibana is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A cross-site scripting (XSS) vulnerability (CVE-2019-7608).

  - An arbitrary code execution flaw in the Timelion visualizer (CVE-2019-7609).

  - An arbitrary code execution flaw in the security audit logger (CVE-2019-7610).

  On May 07, 2021 the NCSC, CISA, FBI and NSA publish advice on detection and mitigation of SVR
  activity following the attribution of the SolarWinds compromise. This VT is covering one or more
  vulnerabilities mentioned in that report." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to obtain
  sensitive information from or perform destructive actions on behalf of other Kibana users.

  Furthermore an attacker with access to the Timelion application could send a request that will
  attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary
  commands with permissions of the Kibana process on the host system.

  Additionally if a Kibana instance has the setting xpack.security.audit.enabled set to true, an
  attacker could send a request that will attempt to execute javascript code. This could possibly
  lead to an attacker executing arbitrary commands with permissions of the Kibana process on the
  host system." );
	script_tag( name: "affected", value: "Kibana versions before 5.6.15 and 6.0.0 before 6.6.1." );
	script_tag( name: "solution", value: "Update to version 5.6.15 or 6.6.1 respectively." );
	script_xref( name: "URL", value: "https://discuss.elastic.co/t/elastic-stack-6-6-1-and-5-6-15-security-update/169077" );
	script_xref( name: "URL", value: "https://www.elastic.co/community/security" );
	script_xref( name: "URL", value: "https://www.ncsc.gov.uk/news/joint-advisory-further-ttps-associated-with-svr-cyber-actors" );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "5.6.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.15", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.6.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.6.1", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

