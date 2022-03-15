CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106744" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-12 08:26:22 +0200 (Wed, 12 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-04 12:10:00 +0000 (Thu, 04 Jun 2020)" );
	script_cve_id( "CVE-2017-6821", "CVE-2017-6813", "CVE-2016-9924" );
	script_bugtraq_id( 97121 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zimbra Collaboration Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zimbra_admin_console_detect.sc" );
	script_mandatory_keys( "zimbra_web/installed" );
	script_tag( name: "summary", value: "Zimbra Collaboration is pronte to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Zimbra Collaboration is pronte to multiple vulnerabilities:

  - Improper handling of privileges (CVE-2017-6813)

  - Improper limitation of file paths (CVE-2017-6821)

  - XML External Entity (XXE) (CVE-2016-9924)" );
	script_tag( name: "affected", value: "Zimbra Collaboration versions before 8.7.6." );
	script_tag( name: "solution", value: "Upgrade to version 8.7.6 or later." );
	script_xref( name: "URL", value: "https://wiki.zimbra.com/wiki/Security_Center" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "8.7.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.7.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

