CPE = "cpe:/a:discourse:discourse";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146396" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-29 07:06:10 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-05 13:31:00 +0000 (Thu, 05 Aug 2021)" );
	script_cve_id( "CVE-2021-32788" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Discourse 2.7.7 Security Update" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_discourse_detect.sc" );
	script_mandatory_keys( "discourse/detected" );
	script_tag( name: "summary", value: "A new Discourse update includes two security fixes." );
	script_tag( name: "insight", value: "The following flaw exists / The following security
  fix is included:

  - CVE-2021-32788: There are two bugs which led to the post creator of a whisper post being
  revealed to non-staff users. Staff users that creates a whisper post in a personal message is
  revealed to non-staff participants of the personal message even though the whisper post cannot
  be seen by them. When a whisper post is before the last post in a post stream, deleting the last
  post will result in the creator of the whisper post to be revealed to non-staff users as the last
  poster of the topic." );
	script_tag( name: "affected", value: "Discourse prior to version 2.7.7." );
	script_tag( name: "solution", value: "Update to version 2.7.7 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://meta.discourse.org/t/2-7-7-security-release/197959" );
	script_xref( name: "URL", value: "https://github.com/discourse/discourse/security/advisories/GHSA-v6xg-q577-vc92" );
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
if(version_is_less( version: version, test_version: "2.7.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

