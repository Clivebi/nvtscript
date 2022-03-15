CPE = "cpe:/a:adobe:connect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817971" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-21085", "CVE-2021-21079", "CVE-2021-21081", "CVE-2021-21080" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-28 13:15:00 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-12 15:19:26 +0530 (Fri, 12 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adobe Connect Multiple Vulnerabilities (APSB21-19)" );
	script_tag( name: "summary", value: "Adobe Connect is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  input validation errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code and conduct arbitrary JavaScript execution in the
  browser." );
	script_tag( name: "affected", value: "Adobe Connect versions 11.0.5 and earlier." );
	script_tag( name: "solution", value: "Upgrade to Adobe Connect version 11.2 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/connect/apsb21-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_adobe_connect_detect.sc" );
	script_mandatory_keys( "adobe/connect/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "11.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 0 );

