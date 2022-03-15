if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100111" );
	script_version( "2020-10-01T11:33:30+0000" );
	script_tag( name: "last_modification", value: "2020-10-01 11:33:30 +0000 (Thu, 01 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-29 10:10:42 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_cve_id( "CVE-1999-0618" );
	script_name( "The rexec service is running" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Useless services" );
	script_dependencies( "rexecd.sc" );
	script_mandatory_keys( "rexec/detected" );
	script_tag( name: "summary", value: "This remote host is running a rexec service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "rexec (remote execution client for an exec server) has the same kind of functionality
  that rsh has: you can execute shell commands on a remote computer.

  The main difference is that rexec authenticate by reading the
  username and password *unencrypted* from the socket." );
	script_tag( name: "solution", value: "Disable the rexec service and use alternatives like SSH instead." );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_kb_item( "rexec/port" )){
	exit( 0 );
}
report = "The rexec service was detected on the target system.";
security_message( data: report, port: port );
exit( 0 );

