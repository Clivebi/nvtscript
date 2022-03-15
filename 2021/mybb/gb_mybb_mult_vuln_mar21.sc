if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113801" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-16 10:32:28 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-23 16:12:00 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2021-27889", "CVE-2021-27890", "CVE-2021-27946", "CVE-2021-27947", "CVE-2021-27948", "CVE-2021-27949" );
	script_name( "MyBB < 1.8.26 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "summary", value: "MyBB is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-27889: Cross-site scripting (XSS) via Nested Auto URL when parsing messages

  - CVE-2021-27890: SQL injection (SQLi) via theme properties included in theme XML files

  - CVE-2021-27946: SQL injection (SQLi) via the poll vote count

  - CVE-2021-27947: SQL injection (SQLi) via the Copy Forum feature in Forum Management

  - CVE-2021-27948: SQL injection (SQLi) via User Groups

  - CVE-2021-27949: Cross-site scripting (XSS) via Custom moderator tools" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  read sensitive information, inject arbitrary HTML or JavaScript into the site
  or even execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "MyBB through version 1.8.25." );
	script_tag( name: "solution", value: "Update to version 1.8.26." );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-xhj7-3349-mqcm" );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-r34m-ccm8-mfhq" );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-23m9-w75q-ph4p" );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-jjx8-8mcp-7h65" );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-3p9w-2q65-r6g2" );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-cmmr-39v8-8rx2" );
	exit( 0 );
}
CPE = "cpe:/a:mybb:mybb";
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
if(version_is_less( version: version, test_version: "1.8.26" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.26", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

