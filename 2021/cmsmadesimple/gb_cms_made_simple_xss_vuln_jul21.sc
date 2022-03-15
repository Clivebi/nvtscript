if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118142" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-06 16:22:04 +0200 (Fri, 06 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 15:07:00 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-23241" );
	script_name( "CMS Made Simple < 2.2.15 XSS Vulnerability (Jul 2021)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to a cross-site scripting
  (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "An authenticated malicious user can take advantage of
  a Stored XSS vulnerability on 'Extra' via 'News > Article'." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated
  attacker to transmit private data, like cookies or other session information,
  redirecting the victim to web content controlled by the attacker, or performing other
  malicious operations on the user's machine under the guise of the vulnerable site." );
	script_tag( name: "affected", value: "CMS Made Simple prior to version 2.2.15." );
	script_tag( name: "solution", value: "Update to version 2.2.15 or later." );
	script_xref( name: "URL", value: "http://dev.cmsmadesimple.org/bug/view/12322" );
	exit( 0 );
}
CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
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
if(version_is_less( version: version, test_version: "2.2.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.15", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

