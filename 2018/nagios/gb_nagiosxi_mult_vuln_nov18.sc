CPE = "cpe:/a:nagios:nagiosxi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141686" );
	script_version( "2021-05-26T08:25:33+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 08:25:33 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-15 09:20:47 +0700 (Thu, 15 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-15708", "CVE-2018-15709", "CVE-2018-15710", "CVE-2018-15711", "CVE-2018-15712", "CVE-2018-15713", "CVE-2018-15714" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nagios XI < 5.5.7 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nagios_XI_detect.sc" );
	script_mandatory_keys( "nagiosxi/installed" );
	script_tag( name: "summary", value: "Nagios XI is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Nagios XI is prone to multiple vulnerabilities:

  - Unauthenticated RCE via Command Argument Injection (CVE-2018-15708)

  - Authenticated Command Injection (CVE-2018-15709)

  - Local Privilege Escalation via Command Injection (CVE-2018-15710)

  - Unauthorized API Key Regeneration (CVE-2018-15711)

  - Unauthenticated Persistent Cross-site Scripting (CVE-2018-15712)

  - Authenticated Persistent Cross-site Scripting (CVE-2018-15713)

  - Reflected Cross-site Scripting (CVE-2018-15714)" );
	script_tag( name: "affected", value: "Nagios XI version 5.5.6 and prior." );
	script_tag( name: "solution", value: "Update to version 5.5.7 or later." );
	script_xref( name: "URL", value: "https://www.nagios.com/products/security/" );
	script_xref( name: "URL", value: "https://www.nagios.com/downloads/nagios-xi/change-log/" );
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
if(version_is_less( version: version, test_version: "5.5.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

