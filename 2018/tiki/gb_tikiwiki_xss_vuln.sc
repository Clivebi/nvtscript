CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140797" );
	script_version( "2021-05-21T08:07:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:07:35 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-23 08:51:05 +0700 (Fri, 23 Feb 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-13 15:01:00 +0000 (Tue, 13 Mar 2018)" );
	script_cve_id( "CVE-2018-7188" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tiki Wiki CMS Groupware XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	script_tag( name: "summary", value: "An XSS vulnerability (via an SVG image) in Tiki allows an authenticated user
to gain administrator privileges if an administrator opens a wiki page with a malicious SVG image, related to
lib/filegals/filegallib.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware prior to version 18.0." );
	script_tag( name: "solution", value: "Upgrade to version 18.0 or later." );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2018/02/16/1" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "18.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

