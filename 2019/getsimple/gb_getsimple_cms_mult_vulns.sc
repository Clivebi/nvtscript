CPE = "cpe:/a:get-simple:getsimple_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142568" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-09 06:02:47 +0000 (Tue, 09 Jul 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-28 19:55:00 +0000 (Mon, 28 Jun 2021)" );
	script_cve_id( "CVE-2019-9915", "CVE-2020-18657", "CVE-2020-18658", "CVE-2020-18659", "CVE-2020-18660", "CVE-2020-18191", "CVE-2021-28976", "CVE-2021-28977" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "GetSimple CMS < 3.3.16 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_getsimple_cms_http_detect.sc" );
	script_mandatory_keys( "getsimple_cms/detected" );
	script_tag( name: "summary", value: "GetSimple CMS is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2019-9915: Open redirect via the 'admin/index.php' redirect parameter

  - CVE-2020-18191: Directory traversal in '/admin/log.php' may allow arbitrary file deletion

  - CVE-2020-18657: Cross Site Scripting (XSS) in 'admin/changedata.php' via the redirect_url
  parameter and the headers_sent function

  - CVE-2020-18658: XSS via the timezone parameter to 'settings.php'

  - CVE-2020-18659: XSS via the (1) sitename, (2) username, and (3) email parameters to
  '/admin/setup.php'

  - CVE-2020-18660: Open redirect in 'admin/changedata.php' via the redirect function to the
  url parameter

  - CVE-2021-28976: Remote Code Execution (RCE) in 'admin/upload.php' via phar files

  - CVE-2021-28977: XSS in 'admin/upload.php' by adding comments or jpg and other file header
  information to the content of xla, pages, and gzip files." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 3.3.16 or later." );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1300" );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1303" );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1310" );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1335" );
	script_xref( name: "URL", value: "https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1336" );
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
if(version_is_less( version: version, test_version: "3.3.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

