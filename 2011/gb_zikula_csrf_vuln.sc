CPE = "cpe:/a:zikula:zikula_application_framework";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801732" );
	script_version( "$Revision: 14168 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_cve_id( "CVE-2011-0535", "CVE-2011-0911" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Zikula CMS CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_zikula_detect.sc" );
	script_mandatory_keys( "zikula/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16097/" );
	script_xref( name: "URL", value: "http://securityreason.com/exploitalert/9921" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/98060/zikulacms-xsrf.txt" );
	script_tag( name: "insight", value: "The flaw exists because the application does not require multiple steps or
  explicit confirmation for sensitive transactions for majority of administrator
  functions such as adding new user, assigning user to administrative privilege." );
	script_tag( name: "solution", value: "Upgrade to the Zikula version 1.2.5." );
	script_tag( name: "summary", value: "This host is running Zikula and is prone to a cross-site request
  forgery vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  commands in the context of the affected site." );
	script_tag( name: "affected", value: "Zikula version 1.2.4 and prior." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.2.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.2.5", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

