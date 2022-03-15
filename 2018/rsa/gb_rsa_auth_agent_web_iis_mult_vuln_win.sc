CPE = "cpe:/a:emc:rsa_authentication_agent_iis";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813118" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-1232", "CVE-2018-1233", "CVE-2018-1234" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-09 15:34:46 +0530 (Mon, 09 Apr 2018)" );
	script_name( "RSA Authentication Agent(IIS) Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with RSA Authentication
  Agent for IIS and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error when handling certain malicious web cookies that have invalid
    formats.

  - Application does not properly filter HTML code from user-supplied input
    before displaying the input.

  - An error where access control list (ACL) permissions on a Windows Named Pipe
    were not sufficient." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause the target service to crash, obtain potentially sensitive information
  and conduct cross-site scripting attacks." );
	script_tag( name: "affected", value: "RSA Authentication Agent for Web for IIS
  version 8.0.1 and earlier." );
	script_tag( name: "solution", value: "Upgrade to version 8.0.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Mar/60" );
	script_xref( name: "URL", value: "https://www.securitytracker.com/id/1040577" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_rsa_auth_agent_detect_win.sc" );
	script_mandatory_keys( "RSA/AuthenticationAgentWebIIS/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
dVer = infos["version"];
dpath = infos["location"];
if(version_is_less( version: dVer, test_version: "8.0.2" )){
	report = report_fixed_ver( installed_version: dVer, fixed_version: "8.0.2", install_path: dpath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

