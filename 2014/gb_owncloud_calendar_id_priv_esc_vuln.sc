CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804285" );
	script_version( "$Revision: 11867 $" );
	script_cve_id( "CVE-2013-2043" );
	script_bugtraq_id( 59966 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-05-06 17:00:55 +0530 (Tue, 06 May 2014)" );
	script_name( "ownCloud 'calendar_id' Parameter privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to privilege escalation
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper verification of input passed via the
'calendar_id' parameter passed to apps/calendar/ajax/events.php when
checking for ownership." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain privilege and
download calendars of other users." );
	script_tag( name: "affected", value: "ownCloud Server 4.5.x before version 4.5.11 and 5.x before 5.0.6" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.5.11 or 5.0.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q2/324" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2013-024" );
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
if(version_in_range( version: ownVer, test_version: "4.5.0", test_version2: "4.5.10" ) || version_in_range( version: ownVer, test_version: "5.0.0", test_version2: "5.0.5" )){
	security_message( port: ownPort );
	exit( 0 );
}

