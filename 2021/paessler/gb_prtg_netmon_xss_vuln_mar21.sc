if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113799" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-11 12:53:05 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-02 20:15:00 +0000 (Wed, 02 Dec 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2020-14073" );
	script_name( "PRTG Network Monitor <= 21.1.66.1623 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker with read/write privileges can create a map
  and then insert JavaScript via the Map Designer Properties." );
	script_tag( name: "affected", value: "PRTG Network Monitor through version 21.1.66.1623." );
	script_tag( name: "solution", value: "No known solution is available as of 11th March, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://gist.github.com/alert3/e058baa33c31695f4168a1dbf77103df" );
	script_xref( name: "URL", value: "https://kb.paessler.com/en/topic/88223-what-s-the-open-vulnerability-report-cve-2020-14073-that-my-security-tracker-informed-me-about" );
	exit( 0 );
}
CPE = "cpe:/a:paessler:prtg_network_monitor";
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
if(version_is_less_equal( version: version, test_version: "21.1.66.1623" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

