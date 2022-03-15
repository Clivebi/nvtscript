CPE = "cpe:/a:sixapart:movable_type";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805357" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2015-1592" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-04-10 15:04:37 +0530 (Fri, 10 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Movable Type Local File Inclusion Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with movable type
  and is prone to arbitrary file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP POST request
  and check whether it is able to upload file or not." );
	script_tag( name: "insight", value: "Flaw is due to he Perl Storable::thaw
  function which allows remote attackers to include and execute arbitrary
  local Perl files and possibly execute arbitrary code." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated remote attacker to upload files and execute arbitrary code
  in an affected site." );
	script_tag( name: "affected", value: "Movable Type before 5.2.12." );
	script_tag( name: "solution", value: "Upgrade to Movable Type 5.2.12." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://exchange.xforce.ibmcloud.com/#/vulnerabilities/100912" );
	script_xref( name: "URL", value: "https://movabletype.org/news/2015/02/movable_type_607_and_5212_released_to_close_security_vulnera.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mt_detect.sc" );
	script_mandatory_keys( "movabletype/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!movVer = get_app_version( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(version_is_less( version: movVer, test_version: "5.2.12" )){
	report = report_fixed_ver( installed_version: movVer, fixed_version: "5.2.12" );
	security_message( data: report, port: http_port );
	exit( 0 );
}
exit( 99 );

