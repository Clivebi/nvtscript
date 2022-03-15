if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117461" );
	script_version( "2021-09-08T10:58:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 10:58:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-05-28 11:07:40 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IKE / ISAKMP Service Detection (UDP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_open_udp_ports.sc", "echo_udp.sc" );
	script_require_udp_ports( "Services/udp/unknown", 500, 4500 );
	script_tag( name: "summary", value: "UDP based detection of services supporting the Internet Key
  Exchange (IKE) Protocol / Internet Security Association and Key Management Protocol (ISAKMP)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("ike_isakmp_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("byte_func.inc.sc");
require("list_array_func.inc.sc");
require("pcap_func.inc.sc");
require("version_func.inc.sc");
require("dump.inc.sc");
proto = "udp";
ports = unknownservice_get_ports( default_port_list: make_list( 500,
	 4500 ), ipproto: proto );
for port in ports {
	if(get_kb_item( "echo_udp/" + port + "/detected" )){
		continue;
	}
	for used_list in make_list( "short_transforms_list",
		 "full_transforms_list" ) {
		if(used_list == "full_transforms_list"){
			sleep( 10 );
		}
		if( used_list == "short_transforms_list" ) {
			use_short_transforms_list = TRUE;
		}
		else {
			use_short_transforms_list = FALSE;
		}
		transforms_info = isakmp_create_transforms_packet_from_list( enable_short_list: use_short_transforms_list );
		if(!transforms_info){
			continue;
		}
		transforms = transforms_info[0];
		transforms_num = transforms_info[1];
		my_initiator_spi = rand_str( length: 8, charset: "abcdefghiklmnopqrstuvwxyz0123456789" );
		req = isakmp_create_request_packet( port: port, ipproto: proto, exchange_type: "Identity Protection (Main Mode)", transforms: transforms, transforms_num: transforms_num, initiator_spi: my_initiator_spi );
		if(!req){
			continue;
		}
		if( use_short_transforms_list ){
			res = isakmp_send_recv( port: port, data: req, initiator_spi: my_initiator_spi, proto: proto, use_pcap: TRUE, debug: FALSE );
		}
		else {
			if(!soc = isakmp_open_socket( port: port, proto: proto )){
				continue;
			}
			res = isakmp_send_recv( soc: soc, data: req, initiator_spi: my_initiator_spi, proto: proto, use_pcap: FALSE, debug: FALSE );
			close( soc );
		}
		if(!res){
			continue;
		}
		ike_vers = res[17];
		if(!ike_vers){
			continue;
		}
		ike_vers_text = VERSIONS[ike_vers];
		if(!ike_vers_text){
			continue;
		}
		if(ike_vers_text == "1.0"){
			set_kb_item( name: "isakmp/v1.0/detected", value: TRUE );
			set_kb_item( name: "isakmp/v1.0/" + proto + "/detected", value: TRUE );
			set_kb_item( name: "isakmp/v1.0/" + proto + "/" + port + "/detected", value: TRUE );
		}
		if( used_list == "full_transforms_list" ) {
			set_kb_item( name: "isakmp/" + proto + "/" + port + "/full_transforms_list_required", value: TRUE );
		}
		else {
			set_kb_item( name: "isakmp/" + proto + "/" + port + "/short_transforms_list_used", value: TRUE );
		}
		set_kb_item( name: "ike/detected", value: TRUE );
		set_kb_item( name: "ike/udp/detected", value: TRUE );
		service_register( port: port, ipproto: proto, proto: "isakmp" );
		log_message( port: port, proto: proto, data: "A service supporting the IKE/ISAKMP protocol is running at this port." );
		break;
	}
}
exit( 0 );

