CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806068" );
	script_version( "2021-07-22T08:07:23+0000" );
	script_cve_id( "CVE-2014-5234", "CVE-2014-5235" );
	script_bugtraq_id( 69796, 69792 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-22 08:07:23 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-10-05 16:02:56 +0530 (Mon, 05 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Vulnerabilities - 01 (Oct 2015)" );
	script_tag( name: "summary", value: "Open-Xchange (OX) AppSuite is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Insufficient sanitization of user-supplied input via a folder publication name

  - Insufficient sanitization of user-supplied input via vectors related to unspecified fields in
  RSS feeds" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of the affected site, potentially
  allowing the attacker to steal cookie-based authentication credentials and control how the site is
  rendered to the user, other attacks are also possible." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite versions before 7.4.2-rev33 and
  7.6.x before 7.6.0-rev16." );
	script_tag( name: "solution", value: "Update to version 7.4.2-rev33, 7.6.0-rev16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/128257" );
	script_xref( name: "URL", value: "http://www.securiteam.com/cves/2014/CVE-2014-5234.html" );
	script_xref( name: "URL", value: "http://www.securiteam.com/cves/2014/CVE-2014-5235.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/533443/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!rev = get_kb_item( "open_xchange_appsuite/" + port + "/revision" )){
	exit( 0 );
}
vers = vers + "." + rev;
if( version_is_less( version: vers, test_version: "7.4.2.33" ) ) {
	fix = "7.4.2-rev33 (7.4.2.33)";
}
else {
	if(IsMatchRegexp( vers, "^7\\.6" ) && version_is_less( version: vers, test_version: "7.6.0.16" )){
		fix = "7.6.0-rev16 (7.6.0.16)";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

