if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100403" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ZABBIX Server/Agent Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service4.sc" );
	script_require_ports( "Services/zabbix", 10050, 10051 );
	script_tag( name: "summary", value: "Detection of a ZABBIX Server/Agent.

  The script sends a connection request to the server and attempts to
  identify the service from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
reqs = make_list( "ZBX_GET_HISTORY_LAST_ID",
	 "{\"request\":\"active checks\",\"host\":\"" + get_host_name() + "\"}" );
ports = service_get_ports( default_port_list: make_list( 10050,
	 10051 ), proto: "zabbix" );
for port in ports {
	for req in reqs {
		soc = open_sock_tcp( port );
		if(!soc){
			break;
		}
		send( socket: soc, data: req );
		buf = recv( socket: soc, length: 1024 );
		close( soc );
		if(isnull( buf )){
			continue;
		}
		if(IsMatchRegexp( buf, "^ZBXD" )){
			service_register( port: port, proto: "zabbix" );
			set_kb_item( name: "Zabbix/installed", value: TRUE );
			set_kb_item( name: "Zabbix/AgentServer/installed", value: TRUE );
			install = port + "/tcp";
			version = "unknown";
			cpe = "cpe:/a:zabbix:zabbix";
			register_product( cpe: cpe, location: install, port: port, service: "zabbix" );
			log_message( data: build_detection_report( app: "Zabbix Server/Agent", version: version, install: install, cpe: cpe, concluded: buf ), port: port );
			break;
		}
	}
}
exit( 0 );

