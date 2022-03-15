CPE = "cpe:/a:plone:plone";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146208" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 04:07:06 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 20:06:00 +0000 (Fri, 02 Jul 2021)" );
	script_cve_id( "CVE-2021-35959" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Plone 5.0.0 <= 5.2.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_plone_detect.sc" );
	script_mandatory_keys( "plone/installed" );
	script_tag( name: "summary", value: "Plone is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Editors are vulnerable to XSS in the folder contents view, if a
  Contributor has created a folder with a SCRIPT tag in the description field." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  inject arbitrary JavaScript into the site." );
	script_tag( name: "affected", value: "Plone version 5.0.0 through 5.2.4." );
	script_tag( name: "solution", value: "Install hotfix package 1.5 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2021/06/30/2" );
	script_xref( name: "URL", value: "https://plone.org/security/hotfix/20210518/stored-xss-in-folder-contents" );
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
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.2.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply hotfix package 1.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

