CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804416" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2013-6188" );
	script_bugtraq_id( 66128 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-03-19 13:49:55 +0530 (Wed, 19 Mar 2014)" );
	script_name( "HP System Management Homepage Cross-Site Request Forgery Vulnerability" );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is prone to
  cross-site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The application allows users to perform certain actions via HTTP requests
  without performing proper validity checks to verify the requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform certain unspecified
  actions when a logged-in user visits a specially crafted web page." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) version 7.1 through 7.2.2." );
	script_tag( name: "solution", value: "Upgrade to HP System Management Homepage (SMH) 7.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57365" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/Mar/61" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2381 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!smhPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!smhVer = get_app_version( cpe: CPE, port: smhPort )){
	exit( 0 );
}
if(version_in_range( version: smhVer, test_version: "7.1", test_version2: "7.2.2" )){
	report = report_fixed_ver( installed_version: smhVer, vulnerable_range: "7.1 - 7.2.2" );
	security_message( port: smhPort, data: report );
	exit( 0 );
}

