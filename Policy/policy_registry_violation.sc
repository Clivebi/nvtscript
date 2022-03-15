if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105990" );
	script_version( "2020-02-06T11:17:59+0000" );
	script_tag( name: "last_modification", value: "2020-02-06 11:17:59 +0000 (Thu, 06 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-05-22 12:45:52 +0700 (Fri, 22 May 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Windows Registry Check: Violations" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/policy_registry.sc" );
	script_mandatory_keys( "policy/registry/started" );
	script_tag( name: "summary", value: "List registry entries which didn't pass the registry
  policy check." );
	script_tag( name: "solution", value: "Update or reconfigure the affected service / system / host according to the
  policy requirement." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
violations = get_kb_list( "policy/registry/violation_list" );
if(violations){
	violations = sort( violations );
	report = "The following registry entries did not pass the registry policy check:\n\n";
	report += "Registry entry | Present | Value checked against | Value set in registry\n";
	for violation in violations {
		report += violation + "\n";
	}
	security_message( port: 0, data: report );
}
exit( 0 );

