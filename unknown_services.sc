require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11154" );
	script_version( "2021-07-12T14:09:10+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 14:09:10 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Collect banner of unknown services" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "apache_SSL_complain.sc", "apcnisd_detect.sc", "asip-status.sc", "auth_enabled.sc", "BigAnt_detect.sc", "bugbear.sc", "check_point_fw1_secureremote_detect.sc", "cheopsNG_detect.sc", "cifs445.sc", "distcc_detection.sc", "dns_server_tcp.sc", "dont_print_on_printers.sc", "echo.sc", "ePo_detect.sc", "find_service_spontaneous.sc", "famd_detect.sc", "find_service6.sc", "gb_ab_ethernet_detect.sc", "gb_aerospike_telnet_detect.sc", "gb_aerospike_xdr_detect.sc", "gb_amqp_detect.sc", "gb_android_adb_detect.sc", "gb_apache_cassandra_detect.sc", "gb_apache_jserv_ajp_detect.sc", "gb_apache_zookeeper_detect.sc", "gb_arkeia_virtual_appliance_detect_617.sc", "gb_backupexec_detect.sc", "gb_check_mk_agent_detect.sc", "gb_chargen_detect_tcp.sc", "gb_cisco_smi_detect.sc", "gb_codesys_detect.sc", "gb_crestron_cip_detect.sc", "gb_dnp3_detect.sc", "gb_dont_scan_fragile_device.sc", "gb_emc_networker_detect.sc", "gb_ethernetip_tcp_detect.sc", "gb_fins_tcp_detect.sc", "gb_freeswitch_mod_event_socket_service_detect.sc", "gb_hid_vertx_discoveryd_detect.sc", "gb_ibm_db2_das_detect.sc", "gb_ibm_soliddb_detect.sc", "gb_ibm_websphere_mq_mqi_detect.sc", "gb_informix_detect.sc", "gb_jdwp_detect.sc", "gb_kerberos_detect.sc", "gb_lantronix_mgm_tcp_detect.sc", "gb_logitech_media_server_tcp_detect.sc", "gb_memcachedb_detect.sc", "gb_memcached_detect.sc", "gb_modbus_detect.sc", "gb_mongodb_detect.sc", "gb_mqtt_detect.sc", "gb_ndmp_detect.sc", "gb_netware_core_protocol_detect.sc", "gb_niagara_fox_detect.sc", "gb_opc_ua_detect.sc", "gb_openvas_administrator_detect.sc", "gb_openvas_manager_detect.sc", "gb_openvpn_detect.sc", "gb_ossec-authd_detect.sc", "gb_visionsoft_audit_detect.sc", "gb_pcworx_detect.sc", "gb_proconos_detect.sc", "gb_qotd_detect_tcp.sc", "gb_redis_detect.sc", "gb_riak_detect.sc", "gb_rlogin_detect.sc", "gb_rmi_registry_detect.sc", "gb_sap_maxdb_detect.sc", "gb_sap_router_detect.sc", "gb_sap_msg_service_detect.sc", "gb_sap_diag_service_detect.sc", "gb_simatic_s7_cotp_detect.sc", "gb_sybase_tcp_listen_detect.sc", "gb_symantec_pcanywhere_access_server_detect.sc", "gb_teamspeak_detect.sc", "gb_winrm_detect.sc", "gnutella_detect.sc", "healthd_detect.sc", "hp_data_protector_installed.sc", "ircd.sc", "ingres_db_detect.sc", "kerio_firewall_admin_port.sc", "kerio_mailserver_admin_port.sc", "kerio_winroute_admin_port.sc", "landesk_detect.sc", "lcdproc_detect.sc", "ldap_detect.sc", "ms_rdp_detect.sc", "mssqlserver_detect.sc", "mysql_version.sc", "nagios_statd_detect.sc", "napster_detect.sc", "nessus_detect.sc", "nntpserver_detect.sc", "ntp_open.sc", "oracle_tnslsnr_version.sc", "ossim_server_detect.sc", "PC_anywhere_tcp.sc", "perforce_detect.sc", "gb_pcl_pjl_detect.sc", "postgresql_detect.sc", "pptp_detect.sc", "qmtp_detect.sc", "radmin_detect.sc", "remote-detect-filemaker.sc", "remote-detect-firebird.sc", "rexecd.sc", "rpcinfo.sc", "rsh.sc", "rtsp_detect.sc", "gb_rsync_remote_detect.sc", "secpod_rpc_portmap_tcp.sc", "SHN_discard.sc", "sip_detection_tcp.sc", "socks.sc", "ssh_detect.sc", "swat_detect.sc", "sw_jenkins_http_detect.sc", "sw_netstat_service_detect.sc", "sw_obby_detect.sc", "sw_policyd-weight_detect.sc", "sw_sphinxsearch_detect.sc", "telnet.sc", "vmware_server_detect.sc", "vnc.sc", "vnc_security_types.sc", "xmpp_detect.sc", "X.sc", "xtel_detect.sc", "xtelw_detect.sc", "yahoo_msg_running.sc", "zabbix_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_sap_gateway_detect.sc", "gsf/gb_atg_service_detect.sc", "gsf/gb_dicom_service_detection.sc", "gsf/gb_hp_imc_dbman_detect.sc", "gsf/gb_pcom_detect.sc", "gsf/gb_drda_detect.sc", "gsf/gb_iec_104_detect.sc", "gsf/gb_melsec_tcp_detect.sc", "gsf/gb_stomp_detect.sc", "gsf/gb_oracle_t3_detect.sc", "gsf/gb_zeromq_detect.sc", "gsf/gb_nimbus_detect.sc", "gsf/gb_sage_adxadmin_detect.sc" );
	}
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin collect the banner from unknown/unidentified services.

  The actual reporting takes place in the separate NVT 'Unknown OS and Service Banner Reporting'
  OID: 1.3.6.1.4.1.25623.1.0.108441." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("dump.inc.sc");
require("port_service_func.inc.sc");
require("string_hex_func.inc.sc");
port = get_kb_item( "Services/unknown" );
if(!port){
	exit( 0 );
}
if(!get_port_state( port )){
	exit( 0 );
}
if(port == 139){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
banner = unknown_banner_report( port: port );
if(!banner){
	exit( 0 );
}
if(strlen( banner[1] ) >= 3){
	set_kb_item( name: "unknown_os_or_service/available", value: TRUE );
	if( ContainsString( banner[0], "Hex" ) ) {
		hexbanner = hexdump( ddata: hex2raw( s: banner[1] ) );
	}
	else {
		hexbanner = hexdump( ddata: banner[1] );
	}
	report = "Method: " + banner[0] + "\n\n" + hexbanner;
	set_kb_item( name: "unknown_service_report/unknown_banner/" + port + "/report", value: report );
}
exit( 0 );

