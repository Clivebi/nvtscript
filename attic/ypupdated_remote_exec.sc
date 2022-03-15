if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80036" );
	script_version( "2021-01-21T13:35:43+0000" );
	script_bugtraq_id( 1749, 28383 );
	script_cve_id( "CVE-1999-0208" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-01-21 13:35:43 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)" );
	script_name( "rpc.ypupdated Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Tenable Network Security, Inc. and Michel Arboi" );
	script_family( "General" );
	script_tag( name: "solution", value: "Remove the '-i' option.
  If this option was not set, the rpc.ypupdated daemon is still vulnerable
  to the old flaw. Contact your vendor for a patch." );
	script_tag( name: "summary", value: "ypupdated with the '-i' option enabled is running on this port." );
	script_tag( name: "insight", value: "ypupdated is part of NIS and allows a client to update NIS maps.

  This old command execution vulnerability was discovered in 1995 and fixed then. However, it is still
  possible to run ypupdated in insecure mode by adding the '-i' option. Anybody can easily run commands
  as root on this machine by specifying an invalid map name that starts with a pipe character. Exploits
  have been publicly available since the first advisory." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

