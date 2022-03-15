if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802775" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-2001", "CVE-2012-2002" );
	script_bugtraq_id( 53340 );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-05-10 17:50:17 +0530 (Thu, 10 May 2012)" );
	script_name( "HP SNMP Agents Open Redirect and Cross-site Scripting Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48978/" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/48978" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522546" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "gb_hp_snmp_agents_detect_lin.sc" );
	script_mandatory_keys( "HP/SNMP/Agents" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute script code in a
  user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "HP SNMP Agents version prior to 9.0.0 on Linux" );
	script_tag( name: "insight", value: "The flaws are due to input is not properly sanitised before being
  returned to the user and being used to redirect users." );
	script_tag( name: "solution", value: "Upgrade to the HP SNMP Agents 9.0.0 or later." );
	script_tag( name: "summary", value: "The host is installed with HP SNMP Agents and is prone to open
  redirect and cross-site scripting vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
hpVer = get_kb_item( "HP/SNMP/Agents" );
if(!hpVer){
	exit( 0 );
}
if(version_is_less( version: hpVer, test_version: "9.0.0" )){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: "9.0.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

