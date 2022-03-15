if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108449" );
	script_version( "$Revision: 12413 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2018-07-05 08:03:26 +0200 (Thu, 05 Jul 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Hostname Determination Reporting" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_END );
	script_family( "Service detection" );
	script_tag( name: "summary", value: "The script reports information on how the hostname
  of the target was determined." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!defined_func( "get_host_names" ) || !defined_func( "get_host_name_source" )){
	exit( 0 );
}
SCRIPT_DESC = "Hostname Determination Reporting";
ip = get_host_ip();
hostnames = get_host_names();
report = "";
hostnames = sort( hostnames );
for hostname in hostnames {
	source = get_host_name_source( hostname: hostname );
	register_host_detail( name: "hostname_determination", value: ip + "," + hostname + "," + source, desc: SCRIPT_DESC );
	report += "\n" + hostname + "|" + source;
}
if(strlen( report ) > 0){
	report = "Hostname determination for IP " + ip + ":\n\nHostname|Source" + report;
	log_message( port: 0, data: report );
}
exit( 0 );

