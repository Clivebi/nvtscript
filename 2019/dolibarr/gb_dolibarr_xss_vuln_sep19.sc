if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113533" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-09-17 11:01:29 +0000 (Tue, 17 Sep 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-17 18:34:00 +0000 (Tue, 17 Sep 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-16197" );
	script_name( "Dolibarr <= 10.0.1 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists within htdocs/societe/card.php,
  where the value of the User-Agent HTTP header is copied
  into the HTML document as plain text between tags." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "Dolibarr through version 10.0.1." );
	script_tag( name: "solution", value: "Update to Dolibarr version 10.0.2 or later." );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/154481/Dolibarr-ERP-CRM-10.0.1-Cross-Site-Scripting.html" );
	script_xref( name: "URL", value: "https://github.com/Monogramm/dolibarr/pull/154" );
	exit( 0 );
}
CPE = "cpe:/a:dolibarr:dolibarr";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "10.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

