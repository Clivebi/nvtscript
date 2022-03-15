CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804362" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-2057" );
	script_bugtraq_id( 66224 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-04-04 16:00:56 +0530 (Fri, 04 Apr 2014)" );
	script_name( "ownCloud Multiple XSS Vulnerabilities-02 Apr14" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to multiple XSS
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to insufficient validation of some unspecified
input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser within the trust relationship between their browser
and the server." );
	script_tag( name: "affected", value: "ownCloud Server before version 6.0.2" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 6.0.2 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57283" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/91975" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2014-007" );
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
if(version_is_less( version: ownVer, test_version: "6.0.2" )){
	report = report_fixed_ver( installed_version: ownVer, fixed_version: "6.0.2" );
	security_message( port: ownPort, data: report );
	exit( 0 );
}

