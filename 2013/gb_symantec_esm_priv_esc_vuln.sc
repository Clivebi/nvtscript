if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803095" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2012-4350" );
	script_bugtraq_id( 56915 );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-01-08 13:22:57 +0530 (Tue, 08 Jan 2013)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Symantec Enterprise Security Manager/Agent Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/ESM/Ver" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027874" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80722" );
	script_xref( name: "URL", value: "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121213_00" );
	script_tag( name: "impact", value: "Successful exploitation could allow local users to gain privileges via
  unspecified vectors." );
	script_tag( name: "affected", value: "Symantec Enterprise Security Manager versions 10.x and prior

  Symantec Enterprise Security Manager Agents versions 10.x and prior" );
	script_tag( name: "insight", value: "An unquoted Windows search path flaw exists in ESM Manager and Agents." );
	script_tag( name: "summary", value: "This host is installed with Symantec Enterprise Security
  Manager/Agent and is prone to local privilege escalation vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Symantec Enterprise Security Manager version 11.0 or later, or apply the patch SU44." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:symantec:enterprise_security_manager";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "11.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.0", install_path: location );
	report = report_fixed_ver( installed_version: version, fixed_version: "11.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

