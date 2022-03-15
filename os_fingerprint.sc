require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102002" );
	script_version( "2021-10-04T09:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 09:24:26 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2009-05-19 12:05:50 +0200 (Tue, 19 May 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (ICMP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_family( "Product detection" );
	script_dependencies( "gb_greenbone_os_consolidation.sc", "gb_ami_megarac_sp_web_detect.sc", "gb_apple_mobile_detect.sc", "gb_apple_macosx_server_detect.sc", "gb_vmware_esx_web_detect.sc", "gb_vmware_esx_snmp_detect.sc", "gb_ssh_cisco_ios_get_version.sc", "gb_cisco_cucmim_version.sc", "gb_cisco_cucm_version.sc", "gb_cisco_nx_os_version.sc", "gb_cyclades_detect.sc", "gb_fortios_detect.sc", "gb_fortimail_consolidation.sc", "gb_cisco_esa_version.sc", "gb_cisco_wsa_version.sc", "gb_cisco_csma_version.sc", "gb_cisco_ip_phone_detect.sc", "gb_cisco_ios_xr_version.sc", "gb_ssh_junos_get_version.sc", "gb_palo_alto_panOS_version.sc", "gb_screenos_version.sc", "gb_extremeos_snmp_detect.sc", "gb_tippingpoint_sms_consolidation.sc", "gb_cisco_asa_version_snmp.sc", "gb_cisco_asa_version.sc", "gb_cisco_asa_http_detect.sc", "gb_cisco_wlc_consolidation.sc", "gb_arista_eos_snmp_detect.sc", "gb_netgear_prosafe_consolidation.sc", "gb_netgear_wnap_consolidation.sc", "gb_netgear_smart_cloud_switch_http_detect.sc", "gb_netgear_dgn2200_http_detect.sc", "gb_netgear_dgnd3700_http_detect.sc", "gb_wd_mybook_live_http_detect.sc", "gb_hirschmann_consolidation.sc", "gb_phoenix_fl_comserver_web_detect.sc", "gb_geneko_router_consolidation.sc", "gb_option_cloudgate_consolidation.sc", "gb_mikrotik_router_routeros_consolidation.sc", "gb_gpon_home_router_detect.sc", "gb_zhone_znid_gpon_consolidation.sc", "gb_teltonika_router_http_detect.sc", "gb_garrettcom_switch_detect.sc", "gb_3com_officeconnect_vpn_firewall_detect.sc", "gb_axis_network_cameras_ftp_detect.sc", "gb_xenserver_version.sc", "gb_cisco_ios_xe_consolidation.sc", "gb_cisco_nam_consolidation.sc", "gb_cisco_small_business_switch_consolidation.sc", "gb_sophos_xg_detect.sc", "gb_sophos_xg_detect_userportal.sc", "gb_mcafee_email_gateway_version.sc", "gb_brocade_netiron_snmp_detect.sc", "gb_brocade_fabricos_consolidation.sc", "gb_arubaos_detect.sc", "gb_cyberoam_umt_ngfw_detect.sc", "gb_aerohive_hiveos_detect.sc", "gb_qnap_nas_detect.sc", "gb_synology_dsm_detect.sc", "gb_drobo_nas_consolidation.sc", "gb_buffalo_airstation_detect.sc", "gb_unraid_http_detect.sc", "gb_seagate_blackarmor_nas_detect.sc", "gb_netsweeper_http_detect.sc", "gb_trendmicro_smart_protection_server_detect.sc", "gb_barracuda_load_balancer_detect.sc", "gb_simatic_s7_version.sc", "gb_simatic_cp_consolidation.sc", "gb_simatic_scalance_consolidation.sc", "gb_siemens_ruggedcom_consolidation.sc", "gb_honeywell_xlweb_consolidation.sc", "gb_easyio_30p_http_detect.sc", "ilo_detect.sc", "gb_ibm_gcm_kvm_webinterface_detect.sc", "gb_watchguard_fireware_detect.sc", "gb_vibnode_consolidation.sc", "gb_hyperip_consolidation.sc", "gb_ruckus_unleashed_http_detect.sc", "gb_avm_fritz_box_detect.sc", "gb_avm_fritz_wlanrepeater_consolidation.sc", "gb_digitalisierungsbox_consolidation.sc", "gb_lancom_devices_consolidation.sc", "gb_draytek_vigor_consolidation.sc", "gb_hp_onboard_administrator_detect.sc", "gb_cisco_ata_consolidation.sc", "gb_cisco_spa_voip_device_detect.sc", "gb_yealink_ip_phone_consolidation.sc", "gb_dlink_dsr_http_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dsl_detect.sc", "gb_dlink_dns_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc", "gb_dlink_dcs_http_detect.sc", "gb_dgs_1500_detect.sc", "gb_linksys_devices_consolidation.sc", "gb_zyxel_ap_http_detect.sc", "gb_wd_mycloud_consolidation.sc", "gb_sangoma_nsc_detect.sc", "gb_intelbras_ncloud_devices_http_detect.sc", "gb_netapp_data_ontap_consolidation.sc", "gb_emc_isilon_onefs_consolidation.sc", "gb_brickcom_network_camera_detect.sc", "gb_ricoh_printer_consolidation.sc", "gb_ricoh_iwb_detect.sc", "gb_lexmark_printer_consolidation.sc", "gb_toshiba_printer_consolidation.sc", "gb_xerox_printer_consolidation.sc", "gb_sato_printer_consolidation.sc", "gb_epson_printer_consolidation.sc", "gb_codesys_os_detection.sc", "gb_simatic_hmi_consolidation.sc", "gb_wago_plc_consolidation.sc", "gb_rockwell_micrologix_consolidation.sc", "gb_rockwell_powermonitor_http_detect.sc", "gb_crestron_cip_detect.sc", "gb_crestron_ctp_detect.sc", "gb_sunny_webbox_remote_detect.sc", "gb_loxone_miniserver_consolidation.sc", "gb_beward_ip_camera_consolidation.sc", "gb_zavio_ip_cameras_detect.sc", "gb_tp_link_ip_cameras_detect.sc", "gb_edgecore_ES3526XA_manager_remote_detect.sc", "gb_pearl_ip_cameras_detect.sc", "gb_qsee_ip_camera_detect.sc", "gb_vicon_industries_network_camera_consolidation.sc", "gb_riverbed_steelcentral_version.sc", "gb_riverbed_steelhead_ssh_detect.sc", "gb_riverbed_steelhead_http_detect.sc", "gb_dell_sonicwall_sma_sra_consolidation.sc", "gb_dell_sonicwall_gms_detection.sc", "gb_grandstream_ucm_consolidation.sc", "gb_grandstream_gxp_consolidation.sc", "gb_moxa_edr_devices_web_detect.sc", "gb_moxa_iologik_devices_consolidation.sc", "gb_moxa_mgate_consolidation.sc", "gb_moxa_nport_consolidation.sc", "gb_cambium_cnpilot_consolidation.sc", "gb_westermo_weos_detect.sc", "gb_windows_cpe_detect.sc", "gb_huawei_ibmc_consolidation.sc", "gb_huawei_VP9660_mcu_detect.sc", "gb_huawei_home_gateway_http_detect.sc", "gb_avtech_avc7xx_dvr_device_detect.sc", "gb_avtech_device_detect.sc", "gather-package-list.sc", "gb_huawei_euleros_consolidation.sc", "gb_cisco_pis_version.sc", "gb_checkpoint_fw_version.sc", "gb_smb_windows_detect.sc", "gb_nec_communication_platforms_detect.sc", "gb_inim_smartlan_consolidation.sc", "gb_dsx_comm_devices_detect.sc", "gb_vmware_vrealize_operations_manager_web_detect.sc", "gb_ssh_os_detection.sc", "gb_openvpn_access_server_consolidation.sc", "gb_accellion_fta_detect.sc", "gb_proxmox_ve_consolidation.sc", "gb_cisco_smi_detect.sc", "gb_pulse_connect_secure_consolidation.sc", "gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.sc", "gb_citrix_netscaler_version.sc", "gb_intel_standard_manageability_detect.sc", "gb_cisco_ucs_director_consolidation.sc", "gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.sc", "gb_junos_snmp_version.sc", "gb_huawei_vrp_network_device_consolidation.sc", "gb_snmp_os_detection.sc", "gb_dns_os_detection.sc", "gb_ftp_os_detection.sc", "smb_nativelanman.sc", "gb_ucs_detect.sc", "gb_cwp_http_detect.sc", "sw_http_os_detection.sc", "sw_mail_os_detection.sc", "sw_telnet_os_detection.sc", "gb_mysql_mariadb_os_detection.sc", "apcnisd_detect.sc", "gb_dahua_devices_detect.sc", "gb_pptp_os_detection.sc", "gb_f5_enterprise_manager_http_detect.sc", "gb_f5_enterprise_manager_ssh_login_detect.sc", "gb_ntp_os_detection.sc", "remote-detect-MDNS.sc", "mssqlserver_detect.sc", "gb_apple_tv_version.sc", "gb_apple_tv_detect.sc", "gb_upnp_os_detection.sc", "gb_sip_os_detection.sc", "gb_check_mk_agent_detect.sc", "ms_rdp_detect.sc", "gb_schneider_clearscada_detect.sc", "dcetest.sc", "gb_fsecure_internet_gatekeeper_http_detect.sc", "secpod_ocs_inventory_ng_detect.sc", "gb_hnap_os_detection.sc", "gb_ident_os_detection.sc", "gb_pi-hole_detect.sc", "gb_citrix_xenmobile_detect.sc", "gb_dnsmasq_consolidation.sc", "gb_dropbear_consolidation.sc", "gb_monit_detect.sc", "gb_rtsp_os_detection.sc", "gb_nntp_os_detection.sc", "gb_siemens_sinema_server_detect.sc", "gb_owa_detect.sc", "gb_openvas_manager_detect.sc", "gb_gsa_detect.sc", "gb_aerospike_consolidation.sc", "gb_artica_detect.sc", "gb_microfocus_filr_consolidation.sc", "gb_altn_mdaemon_consolidation.sc", "gb_elastix_http_detect.sc", "gb_solarwinds_orion_npm_consolidation.sc", "sw_f5_firepass_http_detect.sc", "gb_gate_one_http_detect.sc", "gb_kaseya_vsa_detect.sc", "gb_manageengine_admanager_plus_consolidation.sc", "gb_emc_isilon_insightiq_detect.sc", "gb_android_adb_detect.sc", "netbios_name_get.sc", "global_settings.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_crestron_airmedia_consolidation.sc", "gsf/gb_synetica_datastream_devices_detect_telnet.sc", "gsf/gb_paloalto_globalprotect_portal_detect.sc", "gsf/gb_cisco_vision_dynamic_signage_director_detect.sc", "gsf/gb_tibco_loglogic_http_detect.sc", "gsf/gb_inea_me-rtu_http_detect.sc", "gsf/gb_fortios_sslvpn_portal_detect.sc", "gsf/gb_mult_vendors_wlan_controller_aps_detection.sc", "gsf/gb_dell_emc_powerconnect_consolidation.sc", "gsf/gb_cisco_ind_http_detect.sc", "gsf/gb_cisco_csm_http_detect.sc", "gsf/gb_silverpeak_appliance_consolidation.sc", "gsf/gb_ewon_flexy_cosy_http_detect.sc", "gsf/gb_f5_big_iq_consolidation.sc", "gsf/gb_optergy_proton_consolidation.sc", "gsf/gb_unitronics_plc_pcom_detect.sc", "gsf/gb_sonicwall_email_security_consolidation.sc", "gsf/gb_ruckus_zonedirector_consolidation.sc", "gsf/gb_honeywell_ip-ak2_http_detect.sc", "gsf/gb_siemens_sppa-t3000_app_server_http_detect.sc", "gsf/gb_timetools_ntp_server_http_detect.sc", "gsf/gb_aruba_switches_consolidation.sc", "gsf/gb_trendmicro_apex_central_consolidation.sc", "gsf/gb_auerswald_compact_sip_detect.sc", "gsf/gb_beckhoff_ads_udp_detect.sc", "gsf/gb_apache_activemq_jms_detect.sc", "gsf/gb_citrix_sharefile_storage_controller_http_detect.sc", "gsf/gb_konicaminolta_printer_consolidation.sc", "gsf/gb_ibm_spectrum_protect_plus_consolidation.sc", "gsf/gb_nimbus_os_detection.sc", "gsf/gb_secomea_gatemanager_http_detect.sc", "gsf/gb_symantec_endpoint_protection_manager_http_detect.sc", "gsf/gb_vxworks_consolidation.sc", "gsf/gb_spinetix_player_http_detect.sc", "gsf/gb_spinetix_fusion_http_detect.sc", "gsf/gb_mobileiron_core_http_detect.sc", "gsf/gb_mobileiron_sentry_http_detect.sc", "gsf/gb_bigbluebutton_http_detect.sc", "gsf/gb_observium_http_detect.sc", "gsf/gb_ruckus_iot_controller_http_detect.sc", "gsf/gb_contiki_os_http_detect.sc", "gsf/gb_ethernut_http_detect.sc", "gsf/gb_solarwinds_orion_platform_consolidation.sc", "gsf/gb_ui_edgepower_consolidation.sc", "gsf/gb_zyxel_usg_consolidation.sc", "gsf/gb_cisco_dna_center_http_detect.sc", "gsf/gb_magicflow_msa_gateway_http_detect.sc", "gsf/gb_cisco_smart_software_manager_on_prem_http_detect.sc", "gsf/gb_apache_druid_http_detect.sc", "gsf/gb_abb_ac500_opcua_detect.sc", "gsf/gb_netmotion_mobility_server_http_detect.sc", "gsf/gb_samsung_wlan_ap_http_detect.sc", "gsf/gb_cisco_sdwan_vmanage_consolidation.sc", "gsf/gb_schneider_powerlogic_consolidation.sc", "gsf/gb_nexusdb_http_detect.sc", "gsf/gb_fortilogger_http_detect.sc", "gsf/gb_yealink_device_management_http_detect.sc", "gsf/gb_inspur_clusterengine_http_detect.sc", "gsf/gb_passbolt_consolidation.sc", "gsf/gb_vmware_view_planner_http_detect.sc", "gsf/gb_netapp_cloud_manager_http_detect.sc", "gsf/gb_vmware_workspace_one_access_http_detect.sc", "gsf/gb_cisco_meraki_http_detect.sc", "gsf/gb_clickstudios_passwordstate_consolidation.sc", "gsf/gb_kemp_loadmaster_consolidation.sc", "gsf/gb_voipmonitor_http_detect.sc", "gsf/gb_ivanti_avalanche_http_detect.sc", "gsf/gb_vmware_workspace_one_access_http_detect.sc", "gsf/gb_blackberry_uem_http_detect.sc", "gsf/gb_flir_ax8_consolidation.sc", "gsf/gb_flir_a3xx_series_consolidation.sc", "gsf/gb_flir_neco_platform_ssh_login_detect.sc", "gsf/gb_cisco_hyperflex_data_platform_http_detect.sc", "gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.sc", "gsf/gb_tg8_firewall_http_detect.sc", "gsf/gb_maipu_network_device_http_detect.sc", "gsf/gb_cisco_sdwan_vedge_ssh_login_detect.sc", "gsf/gb_akkadian_provisioning_manager_http_detect.sc", "gsf/gb_circontrol_circarlife_http_detect.sc", "gsf/gb_circontrol_raption_http_detect.sc", "gsf/gb_sonicwall_nsm_http_detect.sc", "gsf/gb_dell_wyse_management_suite_http_detect.sc", "gsf/gb_philips_vue_pacs_http_detect.sc", "gsf/gb_philips_vue_motion_http_detect.sc", "gsf/gb_aruba_instant_http_detect.sc", "gsf/gb_elastic_cloud_enterprise_http_detect.sc", "gsf/gb_aapanel_http_detect.sc", "gsf/gb_ruijie_devices_http_detect.sc", "gsf/gb_cisco_firepower_device_manager_http_detect.sc", "gsf/gb_manageengine_adselfservice_plus_http_detect.sc", "gsf/gb_fatpipe_http_detect.sc" );
	}
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_add_preference( name: "Run routine", type: "checkbox", value: "yes", id: 1 );
	script_xref( name: "URL", value: "http://www.phrack.org/issues.html?issue=57&id=7#article" );
	script_tag( name: "summary", value: "ICMP based OS fingerprinting / detection." );
	script_tag( name: "insight", value: "This script performs ICMP based OS fingerprinting (as
  described by Ofir Arkin and Fyodor Yarochkin in Phrack #57). It can be used to determine
  the remote OS and partly it's version.

  Note: This routine / method is false positive prone (especially in virtualized
  environments) and only the last resort if any other OS detection method is failing). Due
  to this it is possible to disable this routine via the script preferences." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
run_routine = script_get_preference( name: "Run routine", id: 1 );
if(run_routine && ContainsString( run_routine, "no" )){
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
reports = get_kb_list( "os_detection_report/reports/*" );
if(reports && max_index( keys( reports ) ) > 0){
	exit( 0 );
}
ATTEMPTS = 2;
passed = 0;
require("host_details.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (ICMP)";
FINGERPRINTS = make_list( "AIX,cpe:/o:ibm:aix",
	 "AIX 5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
	 "AIX 4.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
	 "",
	 "Apple Mac OS X,cpe:/o:apple:mac_os_x",
	 "Apple Mac OS X 10.2.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.2.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.2,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.3,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.4,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.5,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.6,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.7,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.8,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.3.9,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.4.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "Apple Mac OS X 10.4.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "",
	 "Cisco IOS,cpe:/o:cisco:ios",
	 "Cisco IOS 12.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "Cisco IOS 12.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "Cisco IOS 12.0,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "Cisco IOS 11.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "Cisco IOS 11.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "Cisco IOS 11.1,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "",
	 "FreeBSD,cpe:/o:freebsd:freebsd",
	 "FreeBSD 5.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 5.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 5.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 5.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 5.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 5.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.11,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.10,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.9,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.6.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
	 "FreeBSD 4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
	 "FreeBSD 4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
	 "FreeBSD 4.1.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
	 "FreeBSD 4.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 3.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 2.2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "FreeBSD 2.2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
	 "",
	 "HP UX,cpe:/o:hp:hp-ux",
	 "HP UX 11.0x,y,!0,!0,!0,1,<255,n,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "HP UX 11.0,y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "",
	 "HP JetDirect,cpe:/h:hp:jetdirect",
	 "HP JetDirect ROM A.03.17 EEPROM A.04.09,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
	 "HP JetDirect ROM A.05.03 EEPROM A.05.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
	 "HP JetDirect ROM F.08.01 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM F.08.08 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM F.08.08 EEPROM F.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.05.34 EEPROM G.05.35,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
	 "HP JetDirect ROM G.06.00 EEPROM G.06.00,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.07.02 EEPROM G.07.17,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.07.02 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.07.02 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.07.19 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.07.19 EEPROM G.08.03,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.07.19 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.08.08 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM G.08.21 EEPROM G.08.21,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM H.07.15 EEPROM H.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
	 "HP JetDirect ROM L.20.07 EEPROM L.20.24,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
	 "HP JetDirect ROM R.22.01 EEPROM L.24.08,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
	 "",
	 "Linux Kernel,cpe:/o:linux:kernel",
	 "Linux Kernel 2.6.11,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.10,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.9,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.8,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.7,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.6,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.5,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.4,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.3,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.2,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.1,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.6.0,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.29,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.28,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.27,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.26,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.25,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.24,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.23,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.22,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.21,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.20,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.19,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.4 (I),y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.4,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.3,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.2,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.1,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.4.0,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.26,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.25,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.24,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.23,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.22,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.21,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.20,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.19,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.4,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.3,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.0.36,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.0.34,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "Linux Kernel 2.0.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
	 "",
	 "Microsoft Windows,cpe:/o:microsoft:windows",
	 "Microsoft Windows 2003 Server Enterprise Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2003 Server Standard Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows XP SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows XP SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows XP,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Server Service Pack 4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Server Service Pack 3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Server Service Pack 2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Server Service Pack 1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Server,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Workstation SP4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Workstation SP3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Workstation SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Workstation SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 2000 Workstation,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows Millennium Edition (ME),y,0,!0,!0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Server,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows NT 4 Workstation,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 98 Second Edition (SE),y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 98,y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
	 "Microsoft Windows 95,y,0,!0,!0,1,<32,n,!0,<32,y,!0,<32,n,!0,<32,y,0,0,!0,8,<32,OK,OK,OK,OK,OK",
	 "",
	 "NetBSD,cpe:/o:netbsd:netbsd",
	 "NetBSD 2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.6.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.6.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.5.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.5.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.4.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "NetBSD 1.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
	 "NetBSD 1.3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
	 "NetBSD 1.3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
	 "NetBSD 1.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
	 "",
	 "OpenBSD,cpe:/o:openbsd:openbsd",
	 "OpenBSD 3.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "OpenBSD 3.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "OpenBSD 3.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "OpenBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "OpenBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
	 "OpenBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
	 "OpenBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
	 "OpenBSD 3.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
	 "OpenBSD 2.9,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
	 "OpenBSD 2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
	 "OpenBSD 2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
	 "OpenBSD 2.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
	 "OpenBSD 2.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
	 "OpenBSD 2.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
	 "",
	 "Sun Solaris,cpe:/o:sun:sunos",
	 "Sun Solaris 10 (SunOS 5.10),y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "Sun Solaris 9 (SunOS 5.9),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "Sun Solaris 8 (SunOS 2.8),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "Sun Solaris 7 (SunOS 2.7),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "Sun Solaris 6 (SunOS 2.6),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "Sun Solaris 2.5.1,y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
	 "" );
func _TTL( ttl ){
	if( ttl <= 32 ) {
		num = 32;
	}
	else {
		if( ttl <= 64 ) {
			num = 64;
		}
		else {
			if( ttl <= 128 ) {
				num = 128;
			}
			else {
				num = 255;
			}
		}
	}
	return "<" + num;
}
func ModuleA(  ){
	if(get_kb_item( "ICMPv4/EchoRequest/failed" )){
		return "n,,,,,";
	}
	ICMP_ECHO_REQUEST = 8;
	IP_ID = 0xBABA;
	ICMP_ID = rand() % 65536;
	ip_packet = forge_ip_packet( ip_tos: 6, ip_id: IP_ID, ip_off: IP_DF, ip_p: IPPROTO_ICMP, ip_src: this_host() );
	icmp_packet = forge_icmp_packet( icmp_type: ICMP_ECHO_REQUEST, icmp_code: 123, icmp_seq: 256, icmp_id: ICMP_ID, ip: ip_packet );
	attempt = ATTEMPTS;
	ret = NULL;
	for(;!ret && attempt--;){
		filter = "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 0" + " and icmp[4:2] = " + ICMP_ID;
		ret = send_packet( packet: icmp_packet, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 1 );
	}
	result = "";
	if( ret ){
		passed = 1;
		result = "y";
		if( get_icmp_element( element: "icmp_code", icmp: ret ) == 0 ) {
			result += ",0";
		}
		else {
			result += ",!0";
		}
		received_id = get_ip_element( element: "ip_id", ip: ret );
		if( received_id == 0 ) {
			result += ",0";
		}
		else {
			if( received_id == IP_ID ) {
				result += ",SENT";
			}
			else {
				result += ",!0";
			}
		}
		if( get_ip_element( element: "ip_tos", ip: ret ) == 0 ) {
			result += ",0";
		}
		else {
			result += ",!0";
		}
		if( get_ip_element( element: "ip_off", ip: ret ) & IP_DF ) {
			result += ",1";
		}
		else {
			result += ",0";
		}
		ttl = get_ip_element( element: "ip_ttl", ip: ret );
		ttl = _TTL( ttl );
		result += "," + ttl;
	}
	else {
		result = "n,,,,,";
	}
	return result;
}
func ModuleB(  ){
	ICMP_TIMESTAMP = 13;
	IP_ID = 0xBABA;
	ICMP_ID = rand() % 65536;
	ip_packet = forge_ip_packet( ip_id: IP_ID, ip_p: IPPROTO_ICMP, ip_src: this_host() );
	icmp_packet = forge_icmp_packet( icmp_type: ICMP_TIMESTAMP, icmp_id: ICMP_ID, ip: ip_packet );
	attempt = ATTEMPTS;
	ret = NULL;
	for(;!ret && attempt--;){
		ret = send_packet( packet: icmp_packet, pcap_active: TRUE, pcap_timeout: 1, pcap_filter: "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 14" + " and icmp[4:2] = " + ICMP_ID );
	}
	result = "";
	if( ret ){
		passed = 1;
		result += "y";
		received_id = get_ip_element( element: "ip_id", ip: ret );
		if( received_id == 0 ) {
			result += ",0";
		}
		else {
			if( received_id == IP_ID ) {
				result += ",SENT";
			}
			else {
				result += ",!0";
			}
		}
		ttl = get_ip_element( element: "ip_ttl", ip: ret );
		ttl = _TTL( ttl );
		result += "," + ttl;
	}
	else {
		set_kb_item( name: "ICMPv4/TimestampRequest/failed", value: TRUE );
		result += "n,,";
	}
	return result;
}
func ModuleC(  ){
	ICMP_ADDRMASK = 17;
	IP_ID = 0xBABA;
	ICMP_ID = rand() % 65536;
	ip_packet = forge_ip_packet( ip_id: IP_ID, ip_p: IPPROTO_ICMP, ip_src: this_host() );
	icmp_packet = forge_icmp_packet( icmp_type: ICMP_ADDRMASK, icmp_id: ICMP_ID, data: crap( length: 4, data: raw_string( 0 ) ), ip: ip_packet );
	attempt = ATTEMPTS;
	ret = NULL;
	for(;!ret && attempt--;){
		ret = send_packet( packet: icmp_packet, pcap_active: TRUE, pcap_timeout: 1, pcap_filter: "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 18" + " and icmp[4:2] = " + ICMP_ID );
	}
	result = "";
	if( ret ){
		passed = 1;
		result += "y";
		received_id = get_ip_element( element: "ip_id", ip: ret );
		if( received_id == 0 ) {
			result += ",0";
		}
		else {
			if( received_id == IP_ID ) {
				result += ",SENT";
			}
			else {
				result += ",!0";
			}
		}
		ttl = get_ip_element( element: "ip_ttl", ip: ret );
		ttl = _TTL( ttl );
		result += "," + ttl;
	}
	else {
		set_kb_item( name: "ICMPv4/AddressMaskRequest/failed", value: TRUE );
		result += "n,,";
	}
	return result;
}
func ModuleD(  ){
	ICMP_INFOREQ = 15;
	IP_ID = 0xBABA;
	ICMP_ID = rand() % 65536;
	ip_packet = forge_ip_packet( ip_id: IP_ID, ip_p: IPPROTO_ICMP, ip_src: this_host() );
	icmp_packet = forge_icmp_packet( icmp_type: ICMP_INFOREQ, icmp_id: ICMP_ID, ip: ip_packet );
	attempt = ATTEMPTS;
	ret = NULL;
	for(;!ret && attempt--;){
		ret = send_packet( packet: icmp_packet, pcap_active: TRUE, pcap_timeout: 1, pcap_filter: "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 16" + " and icmp[4:2] = " + ICMP_ID );
	}
	result = "";
	if( ret ){
		passed = 1;
		result += "y";
		received_id = get_ip_element( element: "ip_id", ip: ret );
		if( received_id == 0 ) {
			result += ",0";
		}
		else {
			if( received_id == IP_ID ) {
				result += ",SENT";
			}
			else {
				result += ",!0";
			}
		}
		ttl = get_ip_element( element: "ip_ttl", ip: ret );
		ttl = _TTL( ttl );
		result += "," + ttl;
	}
	else {
		set_kb_item( name: "ICMPv4/InfoRequest/failed", value: TRUE );
		result = "n,,";
	}
	return result;
}
func ModuleE(  ){
	var dport,udp_packet;
	ICMP_UNREACH_DEF_PORT = 65534;
	IP_ID = 0xBABA;
	ICMP_ID = rand() % 65536;
	ip_packet = forge_ip_packet( ip_id: IP_ID, ip_p: IPPROTO_UDP, ip_off: IP_DF, ip_src: this_host() );
	attempt = ATTEMPTS;
	ret = NULL;
	for(;!ret && attempt--;){
		dport = ICMP_UNREACH_DEF_PORT - attempt;
		udp_packet = forge_udp_packet( data: crap( 70 ), ip: ip_packet, uh_dport: dport, uh_sport: 53 );
		ret = send_packet( packet: udp_packet, pcap_active: TRUE, pcap_timeout: 1, pcap_filter: "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 3" + " and icmp[1:1] = 3 " + " and icmp[30:2] = " + dport );
	}
	result = "";
	if( ret ){
		passed = 1;
		result += "y";
		tos = get_ip_element( ip: ret, element: "ip_tos" );
		if( tos == 0xc0 ) {
			result += ",0xc0";
		}
		else {
			if( tos == 0 ) {
				result += ",0";
			}
			else {
				result += ",!0";
			}
		}
		_3bit_flag_frag_off = get_ip_element( ip: ret, element: "ip_off" );
		if( _3bit_flag_frag_off & IP_DF ) {
			result += ",1";
		}
		else {
			result += ",0";
		}
		received_id = get_ip_element( ip: ret, element: "ip_id" );
		if( received_id == IP_ID ) {
			result += ",SENT";
		}
		else {
			if( received_id == 0 ) {
				result += ",0";
			}
			else {
				result += ",!0";
			}
		}
		echoed_dtsize = get_ip_element( ip: ret, element: "ip_len" ) - 20;
		if( echoed_dtsize == 64 ) {
			reslt += ",64";
		}
		else {
			if( echoed_dtsize > 64 ) {
				result += ",>64";
			}
			else {
				if( echoed_dtsize == 8 ) {
					result += ",8";
				}
				else {
					result += "," + echoed_dtsize;
				}
			}
		}
		hl = get_ip_element( ip: ret, element: "ip_hl" );
		echoed_ip_packet = substr( ret, hl * 4 + 8 );
		echoed_ip_packet_hl = get_ip_element( ip: echoed_ip_packet, element: "ip_hl" );
		echoed_udp_packet = substr( echoed_ip_packet, echoed_ip_packet_hl * 4 );
		reply_ttl = get_ip_element( element: "ip_ttl", ip: ret );
		ip_packet_ttl = get_ip_element( ip: ip_packet, element: "ip_ttl" );
		echoed_ip_packet_ttl = get_ip_element( ip: echoed_ip_packet, element: "ip_ttl" );
		real_ttl = reply_ttl + ip_packet_ttl - echoed_ip_packet_ttl;
		if( real_ttl <= 32 ) {
			result += ",<32";
		}
		else {
			if( real_ttl <= 60 ) {
				result += ",<60";
			}
			else {
				if( real_ttl <= 64 ) {
					result += ",<64";
				}
				else {
					if( real_ttl <= 128 ) {
						result += ",<128";
					}
					else {
						result += ",<255";
					}
				}
			}
		}
		echoed_udp_checksum = get_udp_element( udp: echoed_udp_packet, element: "uh_sum" );
		udp_packet_checksum = get_udp_element( udp: udp_packet, element: "uh_sum" );
		if( echoed_udp_checksum == udp_packet_checksum ) {
			result += ",OK";
		}
		else {
			if( echoed_udp_checksum == 0 ) {
				result += ",0";
			}
			else {
				result += ",BAD";
			}
		}
		echoed_ip_checksum = get_ip_element( ip: echoed_ip_packet, element: "ip_sum" );
		ip_packet_copy = forge_ip_packet( ip_id: IP_ID, ip_p: IPPROTO_UDP, ip_off: IP_DF, ip_src: this_host(), ip_ttl: get_ip_element( ip: echoed_ip_packet, element: "ip_ttl" ) );
		udp_packet_copy = forge_udp_packet( data: crap( 70 ), ip: ip_packet_copy, uh_dport: dport, uh_sport: 53 );
		ip_packet_copy_checksum = get_ip_element( ip: udp_packet_copy, element: "ip_sum" );
		if( echoed_ip_checksum == ip_packet_copy_checksum ) {
			result += ",OK";
		}
		else {
			if( echoed_ip_checksum == 0 ) {
				result += ",0";
			}
			else {
				result += ",BAD";
			}
		}
		original_ip_id = substr( ip_packet, 4, 5 );
		echoed_ip_id = substr( echoed_ip_packet, 4, 5 );
		flipped_original_ip_id = raw_string( substr( original_ip_id, 1 ), substr( original_ip_id, 0, 0 ) );
		if( original_ip_id == echoed_ip_id ) {
			result += ",OK";
		}
		else {
			if( original_ip_id == flipped_original_ip_id ) {
				result += ",FLIPPED";
			}
			else {
				result += ",BAD";
			}
		}
		echoed_total_len = get_ip_element( ip: echoed_ip_packet, element: "ip_len" );
		original_total_len = get_ip_element( ip: udp_packet, element: "ip_len" );
		if( echoed_total_len == original_total_len ) {
			result += ",OK";
		}
		else {
			if( echoed_total_len == original_total_len - 20 ) {
				result += ",<20";
			}
			else {
				if( echoed_total_len == original_total_len + 20 ) {
					result += ",>20";
				}
				else {
					result += ",unexpected";
				}
			}
		}
		echoed_ip_frag_off = get_ip_element( ip: echoed_ip_packet, element: "ip_off" );
		original_ip_frag_off = get_ip_element( ip: ip_packet, element: "ip_off" );
		flipped_original_ip_frag_off = raw_string( substr( original_ip_frag_off, 1 ), substr( original_ip_frag_off, 0, 0 ) );
		if( echoed_ip_frag_off == original_ip_frag_off ) {
			result += ",OK";
		}
		else {
			if( echoed_ip_frag_off == flipped_original_ip_frag_off ) {
				result += ",FLIPPED";
			}
			else {
				result += ",unexpected";
			}
		}
	}
	else {
		set_kb_item( name: "ICMPv4/UDPPortUnreachable/failed", value: TRUE );
		result += "n,,,,,,,,,,";
	}
	return result;
}
result = ModuleA() + "," + ModuleB() + "," + ModuleC() + "," + ModuleD() + "," + ModuleE();
fp = split( buffer: result, sep: ",", keep: 0 );
best_score = 0;
best_os = make_array();
store_sections = FALSE;
if(passed){
	section_title = "";
	for line in FINGERPRINTS {
		if( section_title == "" ){
			extract = split( buffer: line, sep: ",", keep: 0 );
			section_title = extract[0];
			section_cpe = extract[1];
			continue;
		}
		else {
			if( line == "" ){
				section_title = "";
				continue;
			}
			else {
				ar = split( buffer: line, sep: ",", keep: 0 );
				name = ar[0];
				score = 0;
				total = 0;
				for(i = 0;i < max_index( fp );++i){
					if(isnull( fp[i] ) || fp[i] == ""){
						continue;
					}
					total += 1;
					if(!isnull( ar[i + 1] ) && ar[i + 1] != "" && ar[i + 1] == fp[i]){
						score += 1;
					}
				}
				if(total > 0){
					percentage = 100 * score / total;
				}
				if( percentage > best_score ){
					best_score = percentage;
					best_os = make_array( name, section_cpe );
					store_sections = FALSE;
				}
				else {
					if(percentage == best_score){
						if( !store_sections ){
							best_os = make_array( section_title, section_cpe );
							store_sections = TRUE;
						}
						else {
							best_os[section_title] = section_cpe;
						}
					}
				}
			}
		}
	}
}
if(best_score == 0){
	best_os = "Unknown";
}
if( NASLTypeof( best_os ) == "array" ){
	report = "\n(" + best_score + "% confidence)\n";
	for ostitle in keys( best_os ) {
		report += "\n" + ostitle;
	}
	i = 0;
	for ostitle in keys( best_os ) {
		i++;
		set_kb_item( name: "Host/OS/ICMP", value: ostitle );
		set_kb_item( name: "Host/OS/ICMP/Confidence", value: best_score );
		if(ContainsString( tolower( report ), "linux" ) || ContainsString( tolower( report ), "bsd" ) || ContainsString( tolower( report ), "mac os x" )){
			if(!ContainsString( tolower( report ), "windows" )){
				runs_key = "unixoide";
			}
		}
		if(ContainsString( tolower( report ), "windows" )){
			if(!ContainsString( tolower( report ), "linux" ) && !ContainsString( tolower( report ), "bsd" ) && !ContainsString( tolower( report ), "mac os x" )){
				runs_key = "windows";
			}
		}
		if(!runs_key){
			runs_key = "unixoide";
		}
		os_register_and_report( os: ostitle, cpe: best_os[ostitle], banner_type: "ICMP based OS fingerprint", desc: SCRIPT_DESC, port: i, proto: "icmp", runs_key: runs_key );
	}
}
else {
	set_kb_item( name: "Host/OS/ICMP", value: best_os );
	set_kb_item( name: "Host/OS/ICMP/Confidence", value: best_score );
}
exit( 0 );

