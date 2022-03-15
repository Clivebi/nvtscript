CPE = "cpe:/a:atlassian:confluence";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106113" );
	script_version( "2019-10-15T06:15:50+0000" );
	script_tag( name: "last_modification", value: "2019-10-15 06:15:50 +0000 (Tue, 15 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-07-04 12:33:39 +0700 (Mon, 04 Jul 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2015-8398", "CVE-2015-8399" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Atlassian Confluence Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_confluence_detect.sc" );
	script_mandatory_keys( "atlassian/confluence/detected" );
	script_tag( name: "summary", value: "Atlassian Confluence is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Atlassian Confluence is prone to two vulnerabilities:

  Cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or HTML
  via the PATH_INFO to rest/prototype/1/session/check. (CVE-2015-8398)

  Remote authenticated users may read configuration files via the decoratorName parameter to
  spaces/viewdefaultdecorator.action or admin/viewdefaultdecorator.action. (CVE-2015-8399)" );
	script_tag( name: "impact", value: "Unauthenticated remote attackers may inject arbitrary scripts.
  Authenticated attackers may read configuration files." );
	script_tag( name: "affected", value: "Version 5.8.16 and previous." );
	script_tag( name: "solution", value: "Update to 5.8.17 or later versions." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2016/Jan/9" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.8.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.8.17" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

