if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140167" );
	script_version( "$Revision: 11977 $" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "MQTT Broker Does Not Require Authentication" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-17 16:32:23 +0100 (Fri, 17 Feb 2017)" );
	script_category( ACT_ATTACK );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_require_ports( "Services/mqtt", 8883, 1883 );
	script_tag( name: "summary", value: "The remote MQTT does not require authentication." );
	script_tag( name: "vuldetect", value: "Connect to the remote MQTT broker and check if authentication is needed." );
	script_tag( name: "solution", value: "Enable authentication." );
	script_dependencies( "gb_mqtt_detect.sc" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_mandatory_keys( "mqtt/no_user_pass" );
	script_xref( name: "URL", value: "https://www.heise.de/newsticker/meldung/MQTT-Protokoll-IoT-Kommunikation-von-Reaktoren-und-Gefaengnissen-oeffentlich-einsehbar-3629650.html" );
	exit( 0 );
}
if(!port = get_kb_item( "Services/mqtt" )){
	exit( 0 );
}
if(!get_kb_item( "mqtt/no_user_pass" )){
	exit( 99 );
}
security_message( port: port );
exit( 0 );

