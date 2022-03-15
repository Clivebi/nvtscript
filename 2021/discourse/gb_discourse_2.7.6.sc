CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117565" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-16 05:21:35 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-27 16:38:00 +0000 (Tue, 27 Jul 2021)" );
	script_cve_id( "CVE-2021-32764" );
	script_name( "Discourse 2.7.6 Security Update" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "A new Discourse update includes one security fix." );
	script_tag( name: "insight", value: "The following flaw exists / The following security
  fix is included:

  - CVE-2021-32764: Sanitize YouTube Onebox data. This vulnerability only affects sites which have
  disabled/modified the default content-security-policy." );
	script_tag( name: "affected", value: "Discourse prior to version 2.7.6." );
	script_tag( name: "solution", value: "Update to version 2.7.6 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/2-7-6-security-release/197275" );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/security/advisories/GHSA-9x4c-29xg-56hw" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
if(version_is_less( version: vers, test_version: "2.7.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.7.6", install_path: infos["location"] );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

