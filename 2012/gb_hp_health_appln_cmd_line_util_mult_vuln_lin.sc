if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802776" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-2000" );
	script_bugtraq_id( 53336 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-05-11 10:46:35 +0530 (Fri, 11 May 2012)" );
	script_name( "HP System Health Application and Command Line Utilities Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49051/" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/49051" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522549" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_hp_health_appln_cmd_line_utilities_detect_lin.sc" );
	script_mandatory_keys( "HP/Health/CLU" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code via
  unknown vectors." );
	script_tag( name: "affected", value: "HP System Health Application and Command Line Utilities version prior to 9.0.0 on Linux" );
	script_tag( name: "solution", value: "Upgrade HP System Health Application and Command Line Utilities version to 9.0.0 or later." );
	script_tag( name: "summary", value: "The host is installed with HP System Health Application and Command
  Line Utilities and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors in the application.

  NOTE: Further information is not available." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
hpVer = get_kb_item( "HP/Health/CLU" );
if(!hpVer){
	exit( 0 );
}
if(version_is_less( version: hpVer, test_version: "9.0.0" )){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: "9.0.0" );
	security_message( port: 0, data: report );
}

