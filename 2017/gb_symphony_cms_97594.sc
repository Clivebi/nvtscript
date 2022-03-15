CPE = "cpe:/a:symphony-cms:symphony_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108142" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-7694", "CVE-2017-8876" );
	script_bugtraq_id( 97594 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-25 15:59:00 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-19 06:57:33 +0200 (Wed, 19 Apr 2017)" );
	script_name( "Symphony CMS <= 2.6.11 Remote Code Execution Vulnerability" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_symphony_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "symphony/installed" );
	script_xref( name: "URL", value: "http://www.math1as.com/symphonycms_2.7_exec.txt" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/97594" );
	script_xref( name: "URL", value: "https://github.com/symphonycms/symphony-2/releases/tag/2.7.0" );
	script_tag( name: "summary", value: "This host is installed with Symphony CMS
  and is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to execute code and get a webshell from the back-end. The attacker must
  be authenticated and enter PHP code in the datasource editor or event editor." );
	script_tag( name: "affected", value: "Symphony CMS versions through 2.6.11." );
	script_tag( name: "solution", value: "Upgrade to version 2.7.0 or later." );
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
if(version_is_less_equal( version: vers, test_version: "2.6.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.7.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

