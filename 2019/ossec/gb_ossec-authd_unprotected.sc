if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108547" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-02-09 16:58:00 +0100 (Sat, 09 Feb 2019)" );
	script_name( "Unprotected OSSEC/Wazuh ossec-authd" );
	script_category( ACT_GATHER_INFO );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gb_ossec-authd_detect.sc" );
	script_mandatory_keys( "ossec_wazuh/authd/no_auth" );
	script_tag( name: "summary", value: "The remote OSSEC/Wazuh ossec-authd service is not protected by password
  authentication or client certificate verificiation." );
	script_tag( name: "impact", value: "This issue may be misused by a remote attacker to register arbitrary agents
  at the remote service or overwrite the registration of existing ones taking them out of service." );
	script_tag( name: "vuldetect", value: "Evaluate if the remote OSSEC/Wazuh ossec-authd service is protected by password
  authentication or client certificate verificiation." );
	script_tag( name: "insight", value: "It was possible to connect to the remote OSSEC/Wazuh ossec-authd service without
  providing a password or a valid client certificate." );
	script_tag( name: "solution", value: "Enable password authentication or client certificate verification
  within the configuration of ossec-authd. Please see the manual of this service for more information." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1515, proto: "ossec-authd" );
if(!get_kb_item( "ossec_wazuh/authd/" + port + "/no_auth" )){
	exit( 99 );
}
security_message( port: port );
exit( 0 );

