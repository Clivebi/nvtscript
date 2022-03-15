if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800292" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0301" );
	script_name( "Maildrop Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38367" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55980" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Jan/1023515.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_maildrop_detect.sc" );
	script_mandatory_keys( "Maildrop/Linux/Ver" );
	script_tag( name: "insight", value: "The flaw is due to the error in the 'maildrop/main.C', when run by root
  with the '-d' option, uses the gid of root for execution of the mailfilter file
  in a user's home directory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Maildrop version 2.4.0" );
	script_tag( name: "summary", value: "This host is installed Maildrop and is prone to Privilege Escalation
  vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to gain elevated privileges." );
	script_tag( name: "affected", value: "Maildrop version 2.3.0 and prior." );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/courier/files/" );
	exit( 0 );
}
require("version_func.inc.sc");
mailVer = get_kb_item( "Maildrop/Linux/Ver" );
if(!mailVer){
	exit( 0 );
}
if(version_is_less_equal( version: mailVer, test_version: "2.3.0" )){
	report = report_fixed_ver( installed_version: mailVer, vulnerable_range: "Less than or equal to 2.3.0" );
	security_message( port: 0, data: report );
}

