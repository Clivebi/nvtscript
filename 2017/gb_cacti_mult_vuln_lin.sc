CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140268" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-02 16:54:25 +0700 (Wed, 02 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-12065", "CVE-2017-12066" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti Multiple Vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Cacti is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Cacti is prone to multiple vulnerabilities:

  - spikekill.php in Cactimight allow remote attackers to execute arbitrary code via the avgnan, outlier-start, or
outlier-end parameter. (CVE-2017-12065)

  - Cross-site scripting (XSS) vulnerability in aggregate_graphs.php in Cacti allows remote authenticated users to
inject arbitrary web script or HTML via specially crafted HTTP Referer headers, related to the $cancel_url
variable. (CVE-2017-12066)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Cacti version 1.1.15 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 1.1.16 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/877" );
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
if(version_is_less( version: version, test_version: "1.1.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.16" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

