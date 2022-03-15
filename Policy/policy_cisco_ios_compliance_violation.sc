if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106433" );
	script_version( "2020-02-06T11:17:59+0000" );
	script_tag( name: "last_modification", value: "2020-02-06 11:17:59 +0000 (Thu, 06 Feb 2020)" );
	script_tag( name: "creation_date", value: "2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod", value: "98" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Cisco IOS Compliance Check: Failed" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/policy_cisco_ios_compliance.sc" );
	script_mandatory_keys( "policy/cisco_ios_compliance/failed" );
	script_tag( name: "summary", value: "Lists all the Cisco IOS Compliance Policy Checks which did NOT pass." );
	script_tag( name: "solution", value: "Update or reconfigure the affected service / system / host according to the
  policy requirement." );
	exit( 0 );
}
failed = get_kb_item( "policy/cisco_ios_compliance/failed" );
if(failed){
	failed = split( buffer: failed, keep: FALSE );
	report = max_index( failed ) + " Checks failed:\\n\\n";
	for line in failed {
		entry = split( buffer: line, sep: "||", keep: FALSE );
		report += "Title:       " + entry[0] + "\\n";
		report += "Description: " + entry[1] + "\\n";
		report += "Solution:    " + entry[2] + "\\n";
		if(max_index( entry ) == 4){
			report += "Remediation: " + entry[3] + "\\n";
		}
		report += "\n";
	}
	security_message( port: 0, data: report );
}
exit( 0 );

