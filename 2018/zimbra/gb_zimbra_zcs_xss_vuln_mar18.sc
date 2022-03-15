if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112249" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-03-29 13:30:55 +0100 (Thu, 29 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-05 19:13:00 +0000 (Tue, 05 Mar 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-6882" );
	script_name( "Zimbra ZCS < 8.7.11 Patch 1 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zimbra_admin_console_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zimbra_web/installed" );
	script_tag( name: "summary", value: "XSS Vulnerability in Zimbra Collaboration Suite (ZCS) before 8.7.11 Patch 1 and 8.8.x before 8.8.7." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A cross-site scripting (XSS) vulnerability in the ZmMailMsgView.getAttachmentLinkHtml function
  might allow remote attackers to inject arbitrary web script or HTML via a Content-Location header in an email attachment." );
	script_tag( name: "affected", value: "ZCS before 8.7.11 Patch 1 and 8.8.x before 8.8.7." );
	script_tag( name: "solution", value: "Update to ZCS 8.7.11 Patch 1 or 8.8.7." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Mar/52" );
	script_xref( name: "URL", value: "https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories" );
	exit( 0 );
}
CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "8.7.11" )){
	vuln = TRUE;
	fix = "8.7.11 Patch 1";
}
if(version_in_range( version: version, test_version: "8.8.0", test_version2: "8.8.6" )){
	vuln = TRUE;
	fix = "8.8.7";
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

