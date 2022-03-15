if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108526" );
	script_version( "$Revision: 13011 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-10 09:02:19 +0100 (Thu, 10 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-08 09:37:20 +0100 (Tue, 08 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "AppleShare IP / Apple Filing Protocol (AFP) Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "asip-status.sc" );
	script_mandatory_keys( "asip_afp/iscleartext" );
	script_tag( name: "impact", value: "An attacker can uncover login names and passwords by sniffing traffic to the
  AppleShare IP / Apple Filing Protocol (AFP) service." );
	script_tag( name: "solution", value: "Enable encryption within the service configuration. Please have a look at the
  manual of the software providing this service for more information on the configuration." );
	script_tag( name: "summary", value: "The remote host is running a AppleShare IP / Apple Filing Protocol (AFP) service that
  allows cleartext logins over unencrypted connections." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
port = get_kb_item( "Services/appleshare" );
if(!port){
	port = 548;
}
if(!get_port_state( port )){
	exit( 0 );
}
if(!get_kb_item( "asip_afp/" + port + "/iscleartext" )){
	exit( 99 );
}
uams = get_kb_item( "asip_afp/" + port + "/uams" );
if(uams){
	report = "The following UAMs including the \"Cleartxt Passwrd\" are reported by the service:\n\n" + uams;
}
security_message( port: port, data: report );
exit( 0 );

