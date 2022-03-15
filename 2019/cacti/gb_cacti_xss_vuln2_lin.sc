CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141889" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-18 09:45:58 +0700 (Fri, 18 Jan 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-01 22:15:00 +0000 (Sun, 01 Mar 2020)" );
	script_cve_id( "CVE-2018-20723", "CVE-2018-20724", "CVE-2018-20725", "CVE-2018-20726" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti < 1.2.0 Multiple XSS Vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Cacti is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cacti is prone to multiple cross-site scripting vulnerabilities:

  - Cross-site scripting (XSS) vulnerability in color_templates.php (CVE-2018-20723)

  - Cross-site scripting (XSS) vulnerability in pollers.php (CVE-2018-20724)

  - Cross-site scripting (XSS) vulnerability in graph_templates.php  (CVE-2018-2072)

  - Cross-site scripting (XSS) vulnerability in host.php (CVE-2018-20726)" );
	script_tag( name: "affected", value: "Cacti prior to version 1.2.0." );
	script_tag( name: "solution", value: "Update to version 1.2.0 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/2215" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/2212" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/2214" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/2213" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

