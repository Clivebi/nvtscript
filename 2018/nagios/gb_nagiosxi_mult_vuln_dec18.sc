CPE = "cpe:/a:nagios:nagiosxi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141794" );
	script_version( "2021-05-26T08:25:33+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 08:25:33 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-18 09:52:07 +0700 (Tue, 18 Dec 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-07 18:11:00 +0000 (Mon, 07 Jan 2019)" );
	script_cve_id( "CVE-2018-20171", "CVE-2018-20172" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nagios XI < 5.5.8 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nagios_XI_detect.sc" );
	script_mandatory_keys( "nagiosxi/installed" );
	script_tag( name: "summary", value: "Nagios XI is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Nagios XI is prone to multiple vulnerabilities:

  - XSS Vulnerabilities (CVE-2018-20171, CVE-2018-20172)" );
	script_tag( name: "affected", value: "Nagios XI version 5.5.7 and prior." );
	script_tag( name: "solution", value: "Update to version 5.5.8 or later." );
	script_xref( name: "URL", value: "https://www.nagios.com/downloads/nagios-xi/change-log/" );
	script_xref( name: "URL", value: "https://www.seebug.org/vuldb/ssvid-97713" );
	script_xref( name: "URL", value: "https://www.seebug.org/vuldb/ssvid-97714" );
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
if(version_is_less( version: version, test_version: "5.5.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

