if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112468" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-19 10:33:12 +0100 (Wed, 19 Dec 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-16 22:15:00 +0000 (Thu, 16 Jan 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-18246", "CVE-2018-18247", "CVE-2018-18248", "CVE-2018-18249", "CVE-2018-18250" );
	script_name( "Icinga Web 2 < 2.6.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_icingaweb2_detect.sc" );
	script_mandatory_keys( "icingaweb2/installed" );
	script_tag( name: "summary", value: "Icinga Web 2 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Effects of successful exploitation range from sensitive data disclosure over Denial
  of Service to taking actions of the web application in behalf of the victim through XSS or CSRF." );
	script_tag( name: "affected", value: "Icinga Web 2 through version 2.6.1" );
	script_tag( name: "solution", value: "Update to version 2.6.2 or later. Please see the references for more information." );
	script_xref( name: "URL", value: "https://herolab.usd.de/wp-content/uploads/sites/4/2018/12/usd20180027.txt" );
	script_xref( name: "URL", value: "https://herolab.usd.de/wp-content/uploads/sites/4/2018/12/usd20180029.txt" );
	script_xref( name: "URL", value: "https://herolab.usd.de/wp-content/uploads/sites/4/2018/12/usd20180028.txt" );
	script_xref( name: "URL", value: "https://herolab.usd.de/wp-content/uploads/sites/4/2018/12/usd20180030.txt" );
	exit( 0 );
}
CPE = "cpe:/a:icinga:icinga2";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.0.0", test_version2: "2.6.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.6.2" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

