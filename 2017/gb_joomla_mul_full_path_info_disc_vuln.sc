CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107158" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-27 14:05:12 +0200 (Thu, 27 Apr 2017)" );
	script_cve_id( "CVE-2017-8057" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-03 13:09:00 +0000 (Wed, 03 May 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Joomla! CVE-2017-8057 Multiple Full Path Information Disclosure Vulnerabilities" );
	script_tag( name: "summary", value: "Joomla is vulnerable to multiple full path information
  disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote attackers can exploit these issues to obtain sensitive
  information that may lead to further attacks." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain
  sensitive information." );
	script_tag( name: "affected", value: "Joomla! 3.4.0 through 3.6.5 are vulnerable" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor
  advisory for more information." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/98028" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!Ver = get_app_version( cpe: CPE, port: Port )){
	exit( 0 );
}
if(version_in_range( version: Ver, test_version: "3.4.0", test_version2: "3.6.5" )){
	report = report_fixed_ver( installed_version: Ver, fixed_version: "3.7.0" );
	security_message( data: report, port: Port );
	exit( 0 );
}
exit( 99 );

