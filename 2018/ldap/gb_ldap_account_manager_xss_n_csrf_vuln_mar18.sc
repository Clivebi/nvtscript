CPE = "cpe:/a:ldap_account_manager:ldap_account_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812835" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-8763", "CVE-2018-8764" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-20 17:57:00 +0000 (Fri, 20 Apr 2018)" );
	script_tag( name: "creation_date", value: "2018-03-26 15:34:35 +0530 (Mon, 26 Mar 2018)" );
	script_name( "LDAP Account Manager XSS And CSRF Vulnerabilities Mar18" );
	script_tag( name: "summary", value: "The host is installed with LDAP account
  manager and is prone to XSS and CSRF vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - LDAP account manager fails to sanitize the 'dn' parameter and
    the 'template' parameter of the cmd.php page.

  - LDAP account manager fails to sanitize 'sec_token' parameter of the
    'passwordchange' function in the ajax.php page which is revealed in URL." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to inject and execute JavaScript code in the application context and defeat a
  CSRF protection mechanism to reveal sensitive information via URL." );
	script_tag( name: "affected", value: "LDAP account manager version 6.2. Other
  versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to version 6.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Mar/45" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ldap_account_manager_detect.sc" );
	script_mandatory_keys( "ldap_account_manager/installed" );
	script_xref( name: "URL", value: "https://www.ldap-account-manager.org/lamcms" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!lport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: lport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(vers == "6.2"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.3", install_path: path );
	security_message( port: lport, data: report );
	exit( 0 );
}
exit( 0 );

