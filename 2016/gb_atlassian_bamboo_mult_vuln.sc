CPE = "cpe:/a:atlassian:bamboo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807266" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-8361", "CVE-2014-9757" );
	script_bugtraq_id( 83104, 83107 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-02-19 10:03:11 +0530 (Fri, 19 Feb 2016)" );
	script_name( "Atlassian Bamboo Multiple Vulnerabilities Feb16" );
	script_tag( name: "summary", value: "The host is installed with Atlassian Bamboo
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The Ignite Realtime Smack XMPP API does not validate serialized data
    in an XMPP message.

  - The multiple unspecified services do not require authentication." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary java code, and to obtain sensitive information,
  modify settings, or manage build agents." );
	script_tag( name: "affected", value: "Atlassian Bamboo 2.4 through 5.9.9" );
	script_tag( name: "solution", value: "Upgrade to version 5.9.9 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/BAM-17102" );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/BAM-17099" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_bamboo_detect.sc" );
	script_mandatory_keys( "AtlassianBamboo/Installed" );
	script_xref( name: "URL", value: "https://www.atlassian.com/software/bamboo" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!bambooPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!bambooVer = get_app_version( cpe: CPE, port: bambooPort )){
	exit( 0 );
}
if(version_in_range( version: bambooVer, test_version: "2.4", test_version2: "5.9.8" )){
	report = report_fixed_ver( installed_version: bambooVer, fixed_version: "5.9.9" );
	security_message( data: report, port: bambooPort );
	exit( 0 );
}

