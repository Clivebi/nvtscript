CPE = "cpe:/a:adobe:connect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811480" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-3101", "CVE-2017-3102", "CVE-2017-3103" );
	script_bugtraq_id( 99521, 99517, 99518 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-13 12:18:52 +0530 (Thu, 13 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adobe Connect Multiple Vulnerabilities Jul17" );
	script_tag( name: "summary", value: "The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - User Interface (UI) Misrepresentation of Critical Information.

  - Improper Neutralization of Input During Web Page Generation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct reflected and stored cross-site scripting attacks, UI
  redressing (or clickjacking) attacks." );
	script_tag( name: "affected", value: "Adobe Connect versions before 9.6.2" );
	script_tag( name: "solution", value: "Upgrade to Adobe Connect version 9.6.2 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/connect/apsb17-22.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!acVer = get_app_version( cpe: CPE, port: acPort )){
	exit( 0 );
}
if(version_is_less( version: acVer, test_version: "9.6.2" )){
	report = report_fixed_ver( installed_version: acVer, fixed_version: "9.6.2" );
	security_message( data: report, port: acPort );
	exit( 0 );
}

