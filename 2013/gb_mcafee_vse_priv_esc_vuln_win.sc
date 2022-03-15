if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803320" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2010-5143" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-03-04 10:10:22 +0530 (Mon, 04 Mar 2013)" );
	script_name( "McAfee VirusScan Enterprise Privilege Escalation Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2010-5143" );
	script_xref( name: "URL", value: "https://kc.mcafee.com/corporate/index?page=content&id=SB10014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_mcafee_virusscan_enterprise_detect_win.sc" );
	script_mandatory_keys( "McAfee/VirusScan/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disable Anti-Virus, add
  unwanted exclusions or execute unspecified Metasploit Framework module." );
	script_tag( name: "affected", value: "McAfee VirusScan Enterprise versions prior to 8.8" );
	script_tag( name: "insight", value: "Unspecified flaw allows attackers to escalate privileges." );
	script_tag( name: "solution", value: "Update to McAfee VirusScan Enterprise version 8.8 or later." );
	script_xref( name: "URL", value: "http://www.mcafee.com/us/products/virusscan-enterprise.aspx" );
	script_tag( name: "summary", value: "This host is installed with McAfee VirusScan Enterprise and is
  prone to privilege escalation vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "McAfee/VirusScan/Win/Ver" );
if(version){
	if(version_is_less( version: version, test_version: "8.8" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.8" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

