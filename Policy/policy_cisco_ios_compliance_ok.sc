if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106432" );
	script_version( "$Revision: 11532 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-21 21:07:30 +0200 (Fri, 21 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "98" );
	script_name( "Cisco IOS Compliance Check: Passes" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/policy_cisco_ios_compliance.sc" );
	script_mandatory_keys( "policy/cisco_ios_compliance/passed" );
	script_tag( name: "summary", value: "Lists all the Cisco IOS Compliance Policy Check which passed it." );
	exit( 0 );
}
passed = get_kb_item( "policy/cisco_ios_compliance/passed" );
if(passed){
	passed = split( buffer: passed, keep: FALSE );
	report = max_index( passed ) + " Checks passed:\\n\\n";
	for line in passed {
		entry = split( buffer: line, sep: "||", keep: FALSE );
		report += "Title:           " + entry[0] + "\\n";
		report += "Description:     " + entry[1] + "\\n";
		report += "Regex Check:     " + entry[2] + "\\n";
		report += "Must be present: " + entry[3] + "\\n\\n";
	}
	log_message( data: report, port: 0 );
}
exit( 0 );

