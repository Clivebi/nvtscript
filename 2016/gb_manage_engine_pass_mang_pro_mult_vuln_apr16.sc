CPE = "cpe:/a:manageengine:password_manager_pro";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807677" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-04-26 16:33:12 +0530 (Tue, 26 Apr 2016)" );
	script_name( "ManageEngine Password Manager Pro Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with ManageEngine
  Password Manager Pro and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An improper sanitization of input to the parameter 'password' in
    'AddMail.ve' script.

  - An improper sanitization of input to the parameters 'EMAIL', 'ROLE',
    'OLDROLE' in 'EditUser.do' script.

  - An improper sanitization of input to the parameter 'Rule' in
    'jsp/xmlhttp/AjaxResponse.jsp' script.

  - An improper sanitization of input to the parameters 'Resource' and
    'Account' in '/jsp/xmlhttp/PasswdRetriveAjaxResponse.jsp.' script.

  - A Cross-Site Request Forgery vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code, to escalate privileges, to bypass
  Password policy, to bypass Business Login, to do Password Bruteforce for
  resources accounts and to conduct request forgery attacks." );
	script_tag( name: "affected", value: "ManageEngine Password Manager Pro version
  8.1 build 8102 to 8.3 build 8302 and probably earlier versions." );
	script_tag( name: "solution", value: "Upgrade to ManageEngine Password Manager Pro
  version 8.3 build 8303 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39664" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_pass_mang_pro_detect.sc" );
	script_mandatory_keys( "ManageEngine/Password_Manager/installed" );
	script_require_ports( "Services/www", 7272 );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/passwordmanagerpro/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!mePort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!meVer = get_app_version( cpe: CPE, port: mePort )){
	exit( 0 );
}
if(( version_in_range( version: meVer, test_version: "8102", test_version2: "8302" ) )){
	report = report_fixed_ver( installed_version: meVer, fixed_version: "8.3 build Version 8303" );
	security_message( data: report, port: mePort );
	exit( 0 );
}

