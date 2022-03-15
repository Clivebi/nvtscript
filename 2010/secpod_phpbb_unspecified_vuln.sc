CPE = "cpe:/a:phpbb:phpbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902181" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_cve_id( "CVE-2010-1630" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpBB 'posting.php' Unspecified Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phpbb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpBB/installed" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/05/16/1" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/05/19/5" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/05/18/12" );
	script_xref( name: "URL", value: "http://www.phpbb.com/community/viewtopic.php?f=14&p=9764445" );
	script_tag( name: "impact", value: "It has unknown impact and attack vectors." );
	script_tag( name: "affected", value: "phpBB version before 3.0.5" );
	script_tag( name: "insight", value: "The flaw is due to unspecified error in 'posting.php', which has
  unknown impact and attack vectors related to the use of a 'forum id'." );
	script_tag( name: "solution", value: "Upgrade phpBB to 3.0.5 later." );
	script_tag( name: "summary", value: "This host is running phpBB and is prone to unspecified
  vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.phpbb.com/downloads/" );
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
if(version_is_less( version: vers, test_version: "3.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

