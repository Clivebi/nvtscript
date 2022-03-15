CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804656" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2013-0304" );
	script_bugtraq_id( 58111 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-07-03 11:57:36 +0530 (Thu, 03 Jul 2014)" );
	script_name( "ownCloud 'calid' Parameter privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to privilege escalation
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper verification of input passed via the
'calid' parameter passed to /apps/calendar/export.php when checking for
ownership." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain privilege and
download calendars of other users." );
	script_tag( name: "affected", value: "ownCloud Server 4.5.x before 4.5.7" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.5.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52303" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q1/378" );
	script_xref( name: "URL", value: "http://owncloud.org/security/advisory/?id=oC-SA-2013-007" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ownPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ownVer = get_app_version( cpe: CPE, port: ownPort )){
	exit( 0 );
}
if(version_in_range( version: ownVer, test_version: "4.5.0", test_version2: "4.5.6" )){
	report = report_fixed_ver( installed_version: ownVer, vulnerable_range: "4.5.0 - 4.5.6" );
	security_message( port: ownPort, data: report );
	exit( 0 );
}

