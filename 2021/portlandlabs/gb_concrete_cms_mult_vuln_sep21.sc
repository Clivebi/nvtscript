CPE = "cpe:/a:portlandlabs:concrete_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146833" );
	script_version( "2021-10-05T11:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-10-05 08:51:19 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-10-01 20:36:00 +0000 (Fri, 01 Oct 2021)" );
	script_cve_id( "CVE-2021-22949", "CVE-2021-22950", "CVE-2021-22953", "CVE-2021-40097", "CVE-2021-40098", "CVE-2021-40099", "CVE-2021-40100", "CVE-2021-40102", "CVE-2021-40103", "CVE-2021-40104", "CVE-2021-40105", "CVE-2021-40106", "CVE-2021-40107", "CVE-2021-40108", "CVE-2021-40109" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Concrete CMS < 8.5.6 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "Concrete CMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-22949: CSRF allows an attacker to duplicate files which can lead to UI inconvenience,
  and exhaustion of disk space

  - CVE-2021-22950: CSFR allowing attachments to comments in the conversation section to be deleted

  - CVE-2021-22953: CSRF allows an attacker to clone topics which can lead to UI inconvenience, and
  exhaustion of disk space

  - CVE-2021-40097: Authenticated path traversal leads to remote code execution via uploaded PHP
  code, related to the bFilename parameter

  - CVE-2021-40098: Path traversal leading to RCE via external form by adding a regular expression

  - CVE-2021-40099: Fetching the update json scheme over HTTP leads to remote code execution

  - CVE-2021-40100: Stored XSS can occur in Conversations when the Active Conversation Editor is
  set to Rich Text

  - CVE-2021-40102: Arbitrary File deletion can occur via PHAR deserialization in is_dir

  - CVE-2021-40103: Path Traversal can lead to arbitrary file reading and SSRF

  - CVE-2021-40104: SVG sanitizer bypass

  - CVE-2021-40105: XSS via Markdown Comments

  - CVE-2021-40106: Unauthenticated stored XSS in blog comments via the website field

  - CVE-2021-40107: Stored XSS in comment section/FileManger

  - CVE-2021-40108: CSRF in the calendar

  - CVE-2021-40109: SSRF" );
	script_tag( name: "affected", value: "Concrete CMS versions prior to 8.5.6." );
	script_tag( name: "solution", value: "Update to version 8.5.6 or later." );
	script_xref( name: "URL", value: "https://documentation.concretecms.org/developers/introduction/version-history/856-release-notes" );
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
if(version_is_less( version: version, test_version: "8.5.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

