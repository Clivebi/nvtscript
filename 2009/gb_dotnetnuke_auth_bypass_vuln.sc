CPE = "cpe:/a:dotnetnuke:dotnetnuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800684" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-7100" );
	script_bugtraq_id( 31145 );
	script_name( "DotNetNuke Identity Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH " );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotnetnuke_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dotnetnuke/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allows remote attackers to bypass security
  restrictions via unknown vectors related to a 'unique id' and impersonate
  other users and possibly gain elevated pivileges." );
	script_tag( name: "affected", value: "DotNetNuke versions 4.4.1 to 4.8.4." );
	script_tag( name: "insight", value: "The vulnerability is caused due improper validation of a user identity." );
	script_tag( name: "solution", value: "Upgrade to DotNetNuke version 4.9.0 or later." );
	script_tag( name: "summary", value: "The host is installed with DotNetNuke and is prone to Authentication
  Bypass vulnerability." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/45081" );
	script_xref( name: "URL", value: "http://www.dotnetnuke.com/News/SecurityPolicy/Securitybulletinno21/tabid/1174/Default.aspx" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_in_range( version: vers, test_version: "4.4.1", test_version2: "4.8.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.9.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

