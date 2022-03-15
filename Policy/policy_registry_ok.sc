if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105989" );
	script_version( "$Revision: 11532 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-21 21:07:30 +0200 (Fri, 21 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-05-22 12:45:19 +0700 (Fri, 22 May 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Windows Registry Check: OK" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/policy_registry.sc" );
	script_mandatory_keys( "policy/registry/started" );
	script_tag( name: "summary", value: "List registry entries which pass the registry
  policy check." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
passes = get_kb_list( "policy/registry/ok_list" );
if(passes){
	passes = sort( passes );
	report = "The following registry entries are correct:\n\n";
	report += "Registry entry | Present | Value checked | Value set\n";
	for pass in passes {
		report += pass + "\n";
	}
	log_message( port: 0, data: report );
}
exit( 0 );

