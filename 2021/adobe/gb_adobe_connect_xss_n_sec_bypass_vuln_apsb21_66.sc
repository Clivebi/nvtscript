CPE = "cpe:/a:adobe:connect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818503" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2021-36061", "CVE-2021-36062", "CVE-2021-36063" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-09 14:13:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 00:05:37 +0530 (Fri, 13 Aug 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adobe Connect Cross Site Scripting And Security Bypass Vulnerabilities (APSB21-66)" );
	script_tag( name: "summary", value: "The host is missing an important security
  update according to Adobe August update." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an input validation
  error and violation of secure design principles in Adobe Connect software." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code and bypass security restrictions." );
	script_tag( name: "affected", value: "Adobe Connect versions 11.2.2 and earlier." );
	script_tag( name: "solution", value: "Update Adobe Connect to version 11.2.3 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/connect/apsb21-66.html" );
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
if(version_is_less( version: vers, test_version: "11.2.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.2.3", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 0 );

