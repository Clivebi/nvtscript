if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105238" );
	script_version( "$Revision: 9337 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-04-05 16:12:37 +0200 (Thu, 05 Apr 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-16 10:53:07 +0100 (Mon, 16 Mar 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Possible Backdoor" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Malware" );
	script_dependencies( "find_service2.sc" );
	script_mandatory_keys( "possible/backdoor" );
	script_tag( name: "summary", value: "Look for potential backdoors." );
	script_tag( name: "solution", value: "Clean up the target host from the potential backdoor." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(port = get_kb_item( "possible/backdoor" )){
	name = get_kb_item( "backdoor/name" );
	security_message( port: port, data: "A backdoor (" + name + ") seems to be running on this port." );
	exit( 0 );
}
exit( 99 );

