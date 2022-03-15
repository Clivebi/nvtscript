if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112435" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-22 10:37:11 +0100 (Thu, 22 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-19410", "CVE-2018-19411" );
	script_name( "PRTG Network Monitor <= 18.2.39.1661 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A Local File Inclusion vulnerability allows remote unauthenticated attackers to create users with read-write privileges including
  administrators by overriding attributes of the 'include' directive in /public/login.htm and including and executing
  a '/api/addusers' file. By providing 'id' and 'users' parameters, an attacker can create users with
  read-write privileges including administrators. (CVE-2018-19410)

  - An Improper Authorization vulnerability allows attackers with read-only privileges to
  create users with read-write privileges including administrators via a specially crafted
  HTTP request to /api/addusers. (CVE-2018-19411)" );
	script_tag( name: "affected", value: "PRTG Network Monitor through version 18.2.39.1661." );
	script_tag( name: "solution", value: "Update to version 18.2.40.1683." );
	script_xref( name: "URL", value: "https://www.ptsecurity.com/ww-en/analytics/threatscape/pt-2018-24/" );
	script_xref( name: "URL", value: "https://www.ptsecurity.com/ww-en/analytics/threatscape/pt-2018-25/" );
	exit( 0 );
}
CPE = "cpe:/a:paessler:prtg_network_monitor";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "18.2.40.1683" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.2.40.1683" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

