CPE = "cpe:/a:castlamp:zenbership";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107222" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-9759" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-19 11:59:56 +0200 (Mon, 19 Jun 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-22 18:51:00 +0000 (Thu, 22 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Zenbership 1.0.8 CMS - Multiple SQL Injection Vulnerabilities" );
	script_tag( name: "summary", value: "Zenbership is vulnerable to multiple SQL injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerabilities are located in the error_codes, subscriptions, widget and logins parameters of the ./admin/index.php." );
	script_tag( name: "impact", value: "Attackers with privileged web-application user accounts are able to execute malicious sql commands via GET method
request." );
	script_tag( name: "affected", value: "Zenbership - Content Management System (Web-Application) 1.0.8." );
	script_tag( name: "solution", value: "The developer states that this was already fixed in newer releases,
  therefore install the latest available version to mitigate the issue." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Jun/16" );
	script_xref( name: "URL", value: "https://github.com/castlamp/zenbership/issues/110" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zenbership_cms_detect.sc" );
	script_mandatory_keys( "zenbership/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!Ver = get_app_version( cpe: CPE, port: Port )){
	exit( 0 );
}
if(version_is_equal( version: Ver, test_version: "108" )){
	report = report_fixed_ver( installed_version: Ver, fixed_version: "Install the latest available version" );
	security_message( data: report, port: Port );
	exit( 0 );
}
exit( 99 );

