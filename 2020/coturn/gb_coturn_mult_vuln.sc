CPE = "cpe:/a:coturn:coturn";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143561" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-27 06:40:41 +0000 (Thu, 27 Feb 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-08 19:15:00 +0000 (Wed, 08 Jul 2020)" );
	script_cve_id( "CVE-2020-6061", "CVE-2020-6062" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "coturn <= 4.5.1.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_coturn_http_detect.sc" );
	script_mandatory_keys( "coturn/detected" );
	script_tag( name: "summary", value: "coturn is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "coturn is prone to multiple vulnerabilities:

  - Heap overflow vulnerability (CVE-2020-6061)

  - DoS vulnerability (CVE-2020-6062)" );
	script_tag( name: "affected", value: "coturn version 4.5.1.1 and probably prior." );
	script_tag( name: "solution", value: "Update to version 4.5.1.2 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://talosintelligence.com/vulnerability_reports/TALOS-2020-0984" );
	script_xref( name: "URL", value: "https://talosintelligence.com/vulnerability_reports/TALOS-2020-0985" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "4.5.1.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.1.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

