CPE = "cpe:/a:mcafee:mcafee_agent";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806638" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-7237" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-12-02 11:14:16 +0530 (Wed, 02 Dec 2015)" );
	script_name( "McAfee Agent (MA) Log Viewing Functionality Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with McAfee Agent
  and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the remote log viewing
  functionality where the inputs passed to the URL are not completely validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "McAfee Agent (MA) version 5.x before
  5.0.2" );
	script_tag( name: "solution", value: "Upgrade to McAfee Agent (MA) 5.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://kc.mcafee.com/corporate/index?page=content&id=SB10130" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_mcafee_agent_detect.sc" );
	script_mandatory_keys( "McAfee/Agent/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!agentVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( agentVer, "^5\\." )){
	if(version_is_less( version: agentVer, test_version: "5.0.2.132" )){
		report = "Installed version: " + agentVer + "\n" + "Fixed version:     5.0.2\n";
		security_message( data: report );
		exit( 0 );
	}
}

