CPE = "cpe:/a:atlassian:bitbucket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106760" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-18 11:24:13 +0200 (Tue, 18 Apr 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 18:28:00 +0000 (Fri, 12 Oct 2018)" );
	script_cve_id( "CVE-2016-4320" );
	script_bugtraq_id( 97515 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Atlassian Bitbucket Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_bitbucket_detect.sc" );
	script_mandatory_keys( "atlassian_bitbucket/installed" );
	script_tag( name: "summary", value: "Atlassian Bitbucket is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Atlassian Bitbucket allows remote attackers to read the first line of an
arbitrary file via a directory traversal attack on the pull requests resource." );
	script_tag( name: "affected", value: "Atlassian Bitbucket prior to version 4.7.1." );
	script_tag( name: "solution", value: "Update to version 4.7.1 or later." );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/BSERV-8819" );
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
if(version_is_less( version: version, test_version: "4.7.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

