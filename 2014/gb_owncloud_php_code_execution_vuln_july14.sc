CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804659" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2013-0204" );
	script_bugtraq_id( 57497 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-07-03 14:00:12 +0530 (Thu, 03 Jul 2014)" );
	script_name( "ownCloud PHP Code Execution Vulnerability - July14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to remote code execution
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the input passed via the '/settings/personal.php' script is
not properly sanitized before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary php
code." );
	script_tag( name: "affected", value: "ownCloud Server 4.5.x before 4.5.6" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 4.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51872" );
	script_xref( name: "URL", value: "http://owncloud.org/security/advisory/?id=oC-SA-2013-002" );
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
if(version_in_range( version: ownVer, test_version: "4.5.0", test_version2: "4.5.5" )){
	report = report_fixed_ver( installed_version: ownVer, vulnerable_range: "4.5.0 - 4.5.5" );
	security_message( port: ownPort, data: report );
	exit( 0 );
}

