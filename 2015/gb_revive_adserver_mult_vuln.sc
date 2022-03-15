CPE = "cpe:/a:revive:adserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805415" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-8875", "CVE-2014-8793" );
	script_bugtraq_id( 71721, 71718 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-01-13 17:38:00 +0530 (Tue, 13 Jan 2015)" );
	script_name( "Revive Adserver Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_revive_adserver_detect.sc" );
	script_mandatory_keys( "ReviveAdserver/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23242" );
	script_tag( name: "summary", value: "This host is installed with
  Revive Adserver and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Check for the vulnerable version of
  Revive Adserver" );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - insufficient sanitization of input passed via the 'refresh_page' GET
  parameter to 'report-generate.php' script.

  - insufficient sanitization of input by The XML_RPC_cd function in
  lib/pear/XML/RPC.php in Revive Adserver." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause a denial of service and inject arbitrary web
  script or HTML." );
	script_tag( name: "affected", value: "Revive Adserver version 3.0.5 and prior." );
	script_tag( name: "solution", value: "Upgrade to Revive Adserver version 3.0.6
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.revive-adserver.com" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "3.0.6" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.0.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

