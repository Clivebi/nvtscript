if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105991" );
	script_version( "2021-01-21T10:06:42+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:06:42 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2015-05-22 15:06:15 +0700 (Fri, 22 May 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Windows Registry Check: Errors" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/policy_registry.sc" );
	script_mandatory_keys( "policy/registry/started" );
	script_tag( name: "summary", value: "List registry entries from the registry policy check
  which contain errors." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
general_errors = get_kb_list( "policy/registry/general_error_list" );
invalid_lines = get_kb_list( "policy/registry/invalid_list" );
if(general_errors){
	general_errors = sort( general_errors );
	report += "The following errors occurred during the check:\n\n";
	for error in general_errors {
		report += error + "\n";
	}
	report += "\n";
}
if(invalid_lines){
	invalid_lines = sort( invalid_lines );
	report += "The following invalid lines where identified within the uploaded policy file:\n\n";
	report += "Line|Result|Errorcode;\n";
	for error in invalid_lines {
		report += error + "\n";
	}
	report += "\n";
}
if(strlen( report ) > 0){
	log_message( port: 0, data: report );
}
exit( 0 );

