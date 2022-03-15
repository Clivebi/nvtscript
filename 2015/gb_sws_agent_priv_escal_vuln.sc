CPE = "cpe:/a:symantec:workspace_streaming";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805542" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-1484" );
	script_bugtraq_id( 73925 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-29 16:34:56 +0530 (Wed, 29 Apr 2015)" );
	script_name( "Symantec Workspace Streaming Agent Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Symantec Workspace
  Streaming Agent and is prone to local privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to unquoted search path
  error in the AppMgrService.exe, when installed as a service." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attacker to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Symantec Workspace Streaming Agent version
  7.5 before SP1 HF4." );
	script_tag( name: "solution", value: "Upgrade to Symantec Workspace Streaming Agent
  version 7.5 SP1 HF4 or 7.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150410_00" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_symantec_workspace_streaming_detect.sc" );
	script_mandatory_keys( "Symantec/Workspace/Streaming/Agent/Win6432/Installed" );
	script_xref( name: "URL", value: "http://www.symantec.com/workspace-streaming" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!agentVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: agentVer, test_version: "7.5.0.792" )){
	report = "Installed version: " + agentVer + "\n" + "Fixed version:     " + "7.5 SP1 HF4 (7.5.0.792)" + "\n";
	security_message( data: report );
	exit( 0 );
}

