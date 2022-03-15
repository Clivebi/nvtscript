CPE = "cpe:/a:dotcms:dotcms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106116" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-07-05 08:55:18 +0700 (Tue, 05 Jul 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-23 02:59:00 +0000 (Fri, 23 Dec 2016)" );
	script_cve_id( "CVE-2016-2355", "CVE-2016-3688", "CVE-2016-3971", "CVE-2016-3972", "CVE-2016-4040", "CVE-2016-4803" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "dotCMS Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotcms_detect.sc" );
	script_mandatory_keys( "dotCMS/installed" );
	script_tag( name: "summary", value: "dotCMS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "dotCMS is prone to multiple vulnerabilities:

A SQL injection attack is possible via the Content REST api if the api is set to allow for anonymous
content saving (which is the shipped default). (CVE-2016-2355)

A SQL injection vulnerability allows remote administrators to execute arbitrary SQL commands via the
c0-e3 parameter to dwr/call/plaincall/UserAjax.getUsersList.dwr. (CVE-2016-3688)

A cross-site scripting (XSS) vulnerability in lucene_search.jsp allows remote authenticated administrators
to inject arbitrary web script or HTML via the query parameter to c/portal/layout. (CVE-2016-3971)

A directory traversal vulnerability in the dotTailLogServlet allows remote authenticated administrators
to read arbitrary files via a .. (dot dot) in the fileName parameter. (CVE-2016-3972)

A SQL injection vulnerability in the Workflow Screen allows remote administrators to execute arbitrary
SQL commands via the orderby parameter. (CVE-2016-4040)

A CRLF injection vulnerability in the send email functionality allows remote attackers to inject arbitrary
email headers via CRLF sequences in the subject. (CVE-2016-4803)" );
	script_tag( name: "impact", value: "An attacker may access sensitive information in the dotcms database." );
	script_tag( name: "affected", value: "Version 3.3.1 and previous versions." );
	script_tag( name: "solution", value: "Update to 3.3.2 or later versions." );
	script_xref( name: "URL", value: "http://dotcms.com/security/SI-32" );
	script_xref( name: "URL", value: "http://dotcms.com/security/SI-33" );
	script_xref( name: "URL", value: "http://dotcms.com/security/SI-34" );
	script_xref( name: "URL", value: "http://dotcms.com/security/SI-35" );
	script_xref( name: "URL", value: "http://dotcms.com/security/SI-36" );
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
if(version_is_less( version: version, test_version: "3.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

