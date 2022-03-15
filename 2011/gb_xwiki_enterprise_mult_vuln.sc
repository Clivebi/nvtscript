CPE = "cpe:/a:xwiki:xwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801841" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)" );
	script_cve_id( "CVE-2010-4641", "CVE-2010-4642" );
	script_bugtraq_id( 44601 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "XWiki Enterprise Unspecified SQL Injection and XSS Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42058" );
	script_xref( name: "URL", value: "http://www.xwiki.org/xwiki/bin/view/ReleaseNotes/ReleaseNotesXWikiEnterprise25" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xwiki_enterprise_detect.sc" );
	script_mandatory_keys( "xwiki/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary script
  code or cause SQL Injection attack and gain sensitive information." );
	script_tag( name: "affected", value: "XWiki Enterprise before 2.5." );
	script_tag( name: "insight", value: "The flaws are caused by input validation errors when processing user-supplied
  data and parameters, which could allow remote attackers to execute arbitrary
  script code or manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "Upgrade to XWiki Enterprise 2.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running XWiki Enterprise and is prone to unspecified
  SQL injection and cross site scripting vulnerabilities." );
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
if(version_is_less( version: version, test_version: "2.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

