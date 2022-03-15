CPE = "cpe:/a:adobe:connect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813361" );
	script_version( "2021-05-31T06:00:15+0200" );
	script_cve_id( "CVE-2018-4994" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:15 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-11 12:59:18 +0530 (Fri, 11 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Adobe Connect Authentication Bypass Vulnerability (APSB18-18)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Connect
  and is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an authentication
  bypass error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose sensitive information." );
	script_tag( name: "affected", value: "Adobe Connect versions prior to 9.8.1" );
	script_tag( name: "solution", value: "Upgrade to Adobe Connect version 9.8.1 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/connect/apsb18-18.html" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/adobe-connect/connect-downloads-updates.html" );
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

