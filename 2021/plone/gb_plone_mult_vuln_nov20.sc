CPE = "cpe:/a:plone:plone";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145166" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 06:20:50 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 19:17:00 +0000 (Mon, 04 Jan 2021)" );
	script_cve_id( "CVE-2020-28734", "CVE-2020-28735", "CVE-2020-28736" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Plone < 5.2.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_plone_detect.sc" );
	script_mandatory_keys( "plone/installed" );
	script_tag( name: "summary", value: "Plone is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - XXE via a feature that is explicitly only available to the Manager role (CVE-2020-28734)

  - SSRF via the tracebacks feature (CVE-2020-28735)

  - XXE via a feature that is protected by an unapplied permission of plone.schemaeditor.ManageSchemata (CVE-2020-28736)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Plone prior to version 5.2.3." );
	script_tag( name: "solution", value: "Update to version 5.2.3 or later." );
	script_xref( name: "URL", value: "https://dist.plone.org/release/5.2.3/RELEASE-NOTES.txt" );
	script_xref( name: "URL", value: "https://github.com/plone/Products.CMFPlone/issues/3209" );
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
if(version_is_less( version: version, test_version: "5.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

