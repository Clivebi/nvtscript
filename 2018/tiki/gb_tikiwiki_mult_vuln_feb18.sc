CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812811" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-7302", "CVE-2018-7303", "CVE-2018-7304" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-23 12:13:22 +0530 (Fri, 23 Feb 2018)" );
	script_name( "Tiki Wiki Multiple Vulnerabilities Feb18" );
	script_tag( name: "summary", value: "The host is installed with Tiki Wiki CMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The CMS allows upload of .PNG file which is actually having SVG content without
    checking.

  - The CMS does not validate the user input for special characters.

  - An input validation error in the 'Calendar' component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow an
  attacker to perform a CSV Injection attack to perform malicious activity,
  XSS and HTML injection attack." );
	script_tag( name: "affected", value: "Tiki Wiki version 17.1" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://websecnerd.blogspot.in/2018/01/tiki-wiki-cms-groupware-17.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "17.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 0 );

