CPE = "cpe:/a:adobe:connect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813659" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-4994", "CVE-2018-12804", "CVE-2018-12805" );
	script_bugtraq_id( 104102, 104697, 104696 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-17 17:41:00 +0000 (Mon, 17 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-07-12 10:36:00 +0530 (Thu, 12 Jul 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adobe Connect Multiple Vulnerabilities (APSB18-22)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An insecure library loading error.

  - Multiple authentication bypass errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct session hijacking, escalate privileges, disclose sensitive
  information." );
	script_tag( name: "affected", value: "Adobe Connect versions 9.7.5 and earlier" );
	script_tag( name: "solution", value: "Upgrade to Adobe Connect version 9.8.1 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/connect/apsb18-22.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_adobe_connect_detect.sc" );
	script_mandatory_keys( "adobe/connect/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!acPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: acPort, exit_no_version: TRUE )){
	exit( 0 );
}
acVer = infos["version"];
acPath = infos["location"];
if(version_is_less( version: acVer, test_version: "9.8.1" )){
	report = report_fixed_ver( installed_version: acVer, fixed_version: "9.8.1", install_path: acPath );
	security_message( data: report, port: acPort );
	exit( 0 );
}
exit( 0 );

