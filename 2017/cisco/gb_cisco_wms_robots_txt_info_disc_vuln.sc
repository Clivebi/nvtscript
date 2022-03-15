CPE = "cpe:/a:cisco:webex_meetings_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811043" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2017-6651" );
	script_bugtraq_id( 98387 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-16 13:24:42 +0530 (Tue, 16 May 2017)" );
	script_name( "Cisco WebEx Meetings Server 'robots.txt' Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running Cisco WebEx Meetings
  Server and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an incomplete
  configuration of the 'robots.txt' file on customer-hosted WebEx solutions and
  occurs when the Short URL functionality is not activated." );
	script_tag( name: "impact", value: "Successfully exploiting this issue could allow
  the attacker to obtain scheduled meeting information and potentially allow the
  attacker to attend scheduled, customer meetings." );
	script_tag( name: "affected", value: "Cisco WebEx Meetings Server versions 2.5, 2.6, 2.7 or 2.8." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve25950" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170510-cwms" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_webex_meetings_server_detect.sc" );
	script_mandatory_keys( "cisco/webex/meetings_server/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

