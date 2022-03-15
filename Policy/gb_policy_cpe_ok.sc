if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103963" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 10530 $" );
	script_name( "CPE-based Policy Check OK" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-17 16:15:42 +0200 (Tue, 17 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2014-01-06 11:42:20 +0700 (Mon, 06 Jan 2014)" );
	script_category( ACT_END );
	script_family( "Policy" );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH" );
	script_dependencies( "Policy/gb_policy_cpe.sc" );
	script_mandatory_keys( "policy/cpe/checkfor" );
	script_tag( name: "summary", value: "Shows all CPEs which are either present or missing (depending on what to check for) from CPE-based Policy Check." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
checkfor = get_kb_item( "policy/cpe/checkfor" );
if( checkfor == "present" ){
	present = get_kb_item( "policy/cpe/present" );
	poss_present = get_kb_item( "policy/cpe/possibly_present" );
	if(present){
		report = NASLString( "The following CPEs have been detected on the remote host\\n\\nPolicy-CPE|Detected-CPE\\n" );
		report += present;
	}
	if(poss_present){
		report += NASLString( "\\nThe following CPEs *may* have been detected on the remote host\\n\\nPolicy-CPE|Detected-CPE\\n" );
		report += poss_present;
	}
}
else {
	missing = get_kb_item( "policy/cpe/missing" );
	if(missing){
		report = NASLString( "The following CPEs are missing on the remote Host\\n\\n" );
		report += missing;
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

