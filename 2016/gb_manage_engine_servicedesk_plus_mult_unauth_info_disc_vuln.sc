if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809071" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-10-20 12:16:44 +0530 (Thu, 20 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine ServiceDesk Plus Multiple Unauthorized Information Disclosure Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with
  ManageEngine ServiceDesk Plus and is prone to multiple unauthorized information
  disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:
  an inadequate access control over non-permissible functionalities
  under Request module." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker with low privilege to access non-permissible functionalities." );
	script_tag( name: "affected", value: "ManageEngine ServiceDesk Plus version
  9.2 Build 9207 (Other versions could also be affected)." );
	script_tag( name: "solution", value: "Upgrade to ManageEngine ServiceDesk Plus
  9.2 Build 9228 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40569" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/service-desk/readme-9.2.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manageengine_servicedesk_plus_consolidation.sc" );
	script_mandatory_keys( "manageengine/servicedesk_plus/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "9.2b9229" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.2 (Build 9229)", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

