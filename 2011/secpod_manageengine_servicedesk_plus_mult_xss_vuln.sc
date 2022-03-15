if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902469" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ManageEngine ServiceDesk Plus Multiple Stored XSS Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.manageengine.com/products/service-desk/readme-8.0.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/104365/ZSL-2011-5039.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manageengine_servicedesk_plus_consolidation.sc" );
	script_mandatory_keys( "manageengine/servicedesk_plus/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow an attacker to steal cookie-based authentications and launch
  further attacks." );
	script_tag( name: "affected", value: "ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to an error in,

  - 'WorkOrder.do', 'Problems.cc', 'AddNewProblem.cc', 'ChangeDetails.c' when
  processing the 'reqName' parameter.

  - 'WorkOrder.do' when processing the various parameters.

  - 'AddSolution.do' when handling add action via ' keywords' and 'comment'
  parameters.

  - 'ContractDef.do' when processing the 'supportDetails', 'contractName'
  and 'comments' parameters.

  - 'VendorDef.do' and 'MarkUnavailability.jsp' hen processing the
  'organizationName' and 'COMMENTS' parameters.

  - 'HomePage.do', 'MySchedule.do', and 'WorkOrder.d' when handling the HTTP
  header elements 'referer' and 'accept-language'." );
	script_tag( name: "solution", value: "Upgrade to ManageEngine ServiceDesk Plus 8.0 Build 8015 or later." );
	script_tag( name: "summary", value: "This host is running ManageEngine ServiceDesk Plus and is prone to
  multiple stored cross site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: version, test_version: "8.0b8015" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0 (Build 8015)", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

