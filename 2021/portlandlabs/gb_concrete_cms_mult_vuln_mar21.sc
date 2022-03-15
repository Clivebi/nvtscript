CPE = "cpe:/a:portlandlabs:concrete_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145662" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-29 03:11:18 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 20:42:00 +0000 (Thu, 15 Jul 2021)" );
	script_cve_id( "CVE-2021-3111", "CVE-2021-28145" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Concrete CMS < 8.5.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "Concrete CMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-3111: Stored XSS on express entries H1 report

  - CVE-2021-28145: XSS in Surveys" );
	script_tag( name: "affected", value: "Concrete CMS versions prior to 8.5.5." );
	script_tag( name: "solution", value: "Update to version 8.5.5 or later." );
	script_xref( name: "URL", value: "https://documentation.concrete5.org/developers/introduction/version-history/855-release-notes" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/161600/Concrete5-8.5.4-Cross-Site-Scripting.html" );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5/pull/8335" );
	exit( 0 );
}
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
if(version_is_less( version: version, test_version: "8.5.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

