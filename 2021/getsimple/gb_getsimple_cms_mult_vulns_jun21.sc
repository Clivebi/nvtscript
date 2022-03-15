CPE = "cpe:/a:get-simple:getsimple_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118145" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-09 14:02:57 +0200 (Mon, 09 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-25 18:34:00 +0000 (Fri, 25 Jun 2021)" );
	script_cve_id( "CVE-2020-20389", "CVE-2020-20391", "CVE-2020-21353" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_name( "GetSimple CMS 3.4.0a Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_getsimple_cms_http_detect.sc" );
	script_mandatory_keys( "getsimple_cms/detected" );
	script_tag( name: "summary", value: "GetSimple CMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-20389: XSS in 'admin/edit.php'

  - CVE-2020-20391: XSS in 'admin/snippets.php' via 'Add Snippet' and 'Save snippets'

  - CVE-2020-21353: Stored XSS in '/admin/snippets.php' allows attackers to execute arbitrary web
  scripts or HTML via crafted payload in the 'Edit Snippets' module." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "No known solution is available as of 09th August, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1321" );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1322" );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1319" );
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
if(version_is_equal( version: version, test_version: "3.4.0a" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

