CPE = "cpe:/a:atlassian:confluence";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106791" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-27 09:11:45 +0200 (Thu, 27 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-09 23:46:00 +0000 (Tue, 09 May 2017)" );
	script_cve_id( "CVE-2017-7415" );
	script_bugtraq_id( 97961 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Atlassian Confluence Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_confluence_detect.sc" );
	script_mandatory_keys( "atlassian/confluence/detected" );
	script_tag( name: "summary", value: "Atlassian Confluence is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Confluence drafts diff rest resource made the current content of all
  blogs and pages in Confluence available without authentication by providing a page id or draft id." );
	script_tag( name: "impact", value: "Attackers who can access the Confluence web interface of a vulnerable version
  can use this vulnerability to obtain the content of all blogs and pages inside Confluence provided that they
  first enumerate page or draft ids." );
	script_tag( name: "affected", value: "Atlassian Confluence 6.0.x." );
	script_tag( name: "solution", value: "Update to version 6.0.7 or later versions." );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/CONFSERVER-52222" );
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
if(IsMatchRegexp( version, "^6\\.0" )){
	if(version_is_less( version: version, test_version: "6.0.7" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.0.7" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

