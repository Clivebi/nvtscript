CPE = "cpe:/a:modx:revolution";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108120" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-06 07:42:44 +0200 (Thu, 06 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-10 19:26:00 +0000 (Fri, 10 Jan 2020)" );
	script_cve_id( "CVE-2017-7320", "CVE-2017-7321", "CVE-2017-7322", "CVE-2017-7323", "CVE-2017-7324" );
	script_bugtraq_id( 97228 );
	script_name( "MODX Revolution CMS Multiple Security Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_modx_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "modx_cms/installed" );
	script_xref( name: "URL", value: "https://raw.githubusercontent.com/modxcms/revolution/v2.5.5-pl/core/docs/changelog.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/97228" );
	script_xref( name: "URL", value: "https://mazinahmed.net/services/public-reports/ModX%20-%20Responsible%20Disclosure%20-%20January%202017.pdf" );
	script_tag( name: "summary", value: "MODX Revolution CMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "MODX Revolution CMS is prone to multiple vulnerabilities:

  - setup/controllers/language.php does not properly constrain the language parameter, which allows remote attackers to conduct Cookie-Bombing
  attacks and cause a denial of service (cookie quota exhaustion), or conduct HTTP Response Splitting attacks with resultant XSS, via an invalid
  parameter value.Critical settings visible in MODx.config.

  - The update and package-installation features do not verify X.509 certificates from SSL servers, which allows man-in-the-middle attackers to
  spoof servers and trigger the execution of arbitrary code via a crafted certificate.

  - The update and package-installation features use http://rest.modx.com by default, which allows man-in-the-middle attackers to spoof servers
  and trigger the execution of arbitrary code by leveraging the lack of the HTTPS protection mechanism.

  - setup/controllers/welcome.php allows remote attackers to execute arbitrary PHP code via the config_key parameter to the setup/index.php?action=welcome URI.

  - setup/templates/findcore.php allows remote attackers to execute arbitrary PHP code via the core_path parameter." );
	script_tag( name: "affected", value: "Version 2.5.4 and prior." );
	script_tag( name: "solution", value: "Update to version 2.5.5." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "2.5.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.5.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

