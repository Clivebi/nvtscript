CPE = "cpe:/a:novell:netidentity_client";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900341" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1350" );
	script_bugtraq_id( 34400 );
	script_name( "Novell NetIdentity Agent Pointer Dereference Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0954" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-09-016" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Apr/1021990.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/502514/100/0/threaded" );
	script_xref( name: "URL", value: "http://download.novell.com/Download?buildid=6ERQGPjRZ8o~" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_novell_prdts_detect_win.sc" );
	script_mandatory_keys( "Novell/NetIdentity/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code in the
  context of the affected application with system privileges through a valid IPC$ connection." );
	script_tag( name: "affected", value: "Novell NetIdentity Agent version prior to 1.2.4 on Windows." );
	script_tag( name: "insight", value: "Handling of RPC messages over the XTIERRPCPIPE named pipe in 'xtagent.exe',
  and sending RPC messages that triggers the dereference of an arbitrary pointer which can cause remote code execution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to NetIdentity Client version 1.2.4 or later." );
	script_tag( name: "summary", value: "The host is installed with Novell NetIdentity Agent and is prone
  to remote code execution vulnerability." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.2.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.2.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

