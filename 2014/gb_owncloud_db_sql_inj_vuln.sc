CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804411" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2013-2045" );
	script_bugtraq_id( 59961 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-03-14 13:35:19 +0530 (Fri, 14 Mar 2014)" );
	script_name( "ownCloud 'lib/db.php' SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to SQL injection
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the 'lib/db.php' script not properly sanitizing user
supplied input before using it in SQL queries." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data." );
	script_tag( name: "affected", value: "ownCloud Server 5.0.x before 5.0.6" );
	script_tag( name: "solution", value: "Upgrade to ownCloud 5.0.6 or later." );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q2/324" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2013-019" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: ownVer, test_version: "5.0", test_version2: "5.0.5" )){
	report = report_fixed_ver( installed_version: ownVer, vulnerable_range: "5.0 - 5.0.5" );
	security_message( port: ownPort, data: report );
	exit( 0 );
}

