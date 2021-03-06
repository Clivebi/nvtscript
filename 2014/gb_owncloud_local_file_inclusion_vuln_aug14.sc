CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804821" );
	script_version( "$Revision: 11867 $" );
	script_cve_id( "CVE-2014-4929" );
	script_bugtraq_id( 68975 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-08-25 21:35:23 +0530 (Mon, 25 Aug 2014)" );
	script_name( "ownCloud Local File Inclusion Vulnerability -01 Aug14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to local file inclusion
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the Routing component not properly sanitizing
user-supplied input to the 'filename' parameter in a require_once statement." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to reinstall the instance
overwriting the existing configuration or execute arbitrary PHP code or disclose
the contents of any file on the system." );
	script_tag( name: "affected", value: "ownCloud Server 5.0.x before version 5.0.17, 6.0.x before version 6.0.4" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 5.0.17 or 6.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://owncloud.org/changelog/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59543" );
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
if(IsMatchRegexp( ownVer, "^(5|6)" )){
	if(version_in_range( version: ownVer, test_version: "5.0.0", test_version2: "5.0.16" ) || version_in_range( version: ownVer, test_version: "6.0.0", test_version2: "6.0.3" )){
		security_message( port: ownPort );
		exit( 0 );
	}
}

