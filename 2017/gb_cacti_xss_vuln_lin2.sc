CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140314" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-21 14:09:48 +0700 (Mon, 21 Aug 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-27 01:29:00 +0000 (Sun, 27 Aug 2017)" );
	script_cve_id( "CVE-2017-12927", "CVE-2017-12978" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti XSS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Cross-site scripting (XSS) vulnerabilities in spikekill.php and lib/html.php in Cacti
allow remote attackers to inject arbitrary web scripts or HTML." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Cacti version 1.1.17 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 1.1.18 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/907" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/918" );
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
if(version_is_less( version: version, test_version: "1.1.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.18" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

