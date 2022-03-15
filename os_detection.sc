require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105937" );
	script_version( "2021-10-04T09:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 09:24:26 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2016-02-19 11:19:54 +0100 (Fri, 19 Feb 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OS Detection Consolidation and Reporting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_greenbone_os_consolidation.sc", "gb_ami_megarac_sp_web_detect.sc", "gb_apple_mobile_detect.sc", "gb_apple_macosx_server_detect.sc", "gb_vmware_esx_web_detect.sc", "gb_vmware_esx_snmp_detect.sc", "gb_ssh_cisco_ios_get_version.sc", "gb_cisco_cucmim_version.sc", "gb_cisco_cucm_version.sc", "gb_cisco_nx_os_version.sc", "gb_cyclades_detect.sc", "gb_fortios_detect.sc", "gb_fortimail_consolidation.sc", "gb_cisco_esa_version.sc", "gb_cisco_wsa_version.sc", "gb_cisco_csma_version.sc", "gb_cisco_ip_phone_detect.sc", "gb_cisco_ios_xr_version.sc", "gb_ssh_junos_get_version.sc", "gb_palo_alto_panOS_version.sc", "gb_screenos_version.sc", "gb_extremeos_snmp_detect.sc", "gb_tippingpoint_sms_consolidation.sc", "gb_cisco_asa_version_snmp.sc", "gb_cisco_asa_version.sc", "gb_cisco_asa_http_detect.sc", "gb_cisco_wlc_consolidation.sc", "gb_arista_eos_snmp_detect.sc", "gb_netgear_prosafe_consolidation.sc", "gb_netgear_wnap_consolidation.sc", "gb_netgear_smart_cloud_switch_http_detect.sc", "gb_netgear_dgn2200_http_detect.sc", "gb_netgear_dgnd3700_http_detect.sc", "gb_wd_mybook_live_http_detect.sc", "gb_hirschmann_consolidation.sc", "gb_phoenix_fl_comserver_web_detect.sc", "gb_geneko_router_consolidation.sc", "gb_option_cloudgate_consolidation.sc", "gb_mikrotik_router_routeros_consolidation.sc", "gb_gpon_home_router_detect.sc", "gb_zhone_znid_gpon_consolidation.sc", "gb_teltonika_router_http_detect.sc", "gb_garrettcom_switch_detect.sc", "gb_3com_officeconnect_vpn_firewall_detect.sc", "gb_axis_network_cameras_ftp_detect.sc", "gb_xenserver_version.sc", "gb_cisco_ios_xe_consolidation.sc", "gb_cisco_nam_consolidation.sc", "gb_cisco_small_business_switch_consolidation.sc", "gb_sophos_xg_detect.sc", "gb_sophos_xg_detect_userportal.sc", "gb_mcafee_email_gateway_version.sc", "gb_brocade_netiron_snmp_detect.sc", "gb_brocade_fabricos_consolidation.sc", "gb_arubaos_detect.sc", "gb_cyberoam_umt_ngfw_detect.sc", "gb_aerohive_hiveos_detect.sc", "gb_qnap_nas_detect.sc", "gb_synology_dsm_detect.sc", "gb_drobo_nas_consolidation.sc", "gb_buffalo_airstation_detect.sc", "gb_unraid_http_detect.sc", "gb_seagate_blackarmor_nas_detect.sc", "gb_netsweeper_http_detect.sc", "gb_trendmicro_smart_protection_server_detect.sc", "gb_barracuda_load_balancer_detect.sc", "gb_simatic_s7_version.sc", "gb_simatic_cp_consolidation.sc", "gb_simatic_scalance_consolidation.sc", "gb_siemens_ruggedcom_consolidation.sc", "gb_honeywell_xlweb_consolidation.sc", "gb_easyio_30p_http_detect.sc", "ilo_detect.sc", "gb_ibm_gcm_kvm_webinterface_detect.sc", "gb_watchguard_fireware_detect.sc", "gb_vibnode_consolidation.sc", "gb_hyperip_consolidation.sc", "gb_ruckus_unleashed_http_detect.sc", "gb_avm_fritz_box_detect.sc", "gb_avm_fritz_wlanrepeater_consolidation.sc", "gb_digitalisierungsbox_consolidation.sc", "gb_lancom_devices_consolidation.sc", "gb_draytek_vigor_consolidation.sc", "gb_hp_onboard_administrator_detect.sc", "gb_cisco_ata_consolidation.sc", "gb_cisco_spa_voip_device_detect.sc", "gb_yealink_ip_phone_consolidation.sc", "gb_dlink_dsr_http_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dsl_detect.sc", "gb_dlink_dns_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc", "gb_dlink_dcs_http_detect.sc", "gb_dgs_1500_detect.sc", "gb_linksys_devices_consolidation.sc", "gb_zyxel_ap_http_detect.sc", "gb_wd_mycloud_consolidation.sc", "gb_sangoma_nsc_detect.sc", "gb_intelbras_ncloud_devices_http_detect.sc", "gb_netapp_data_ontap_consolidation.sc", "gb_emc_isilon_onefs_consolidation.sc", "gb_brickcom_network_camera_detect.sc", "gb_ricoh_printer_consolidation.sc", "gb_ricoh_iwb_detect.sc", "gb_lexmark_printer_consolidation.sc", "gb_toshiba_printer_consolidation.sc", "gb_xerox_printer_consolidation.sc", "gb_sato_printer_consolidation.sc", "gb_epson_printer_consolidation.sc", "gb_codesys_os_detection.sc", "gb_simatic_hmi_consolidation.sc", "gb_wago_plc_consolidation.sc", "gb_rockwell_micrologix_consolidation.sc", "gb_rockwell_powermonitor_http_detect.sc", "gb_crestron_cip_detect.sc", "gb_crestron_ctp_detect.sc", "gb_sunny_webbox_remote_detect.sc", "gb_loxone_miniserver_consolidation.sc", "gb_beward_ip_camera_consolidation.sc", "gb_zavio_ip_cameras_detect.sc", "gb_tp_link_ip_cameras_detect.sc", "gb_edgecore_ES3526XA_manager_remote_detect.sc", "gb_pearl_ip_cameras_detect.sc", "gb_qsee_ip_camera_detect.sc", "gb_vicon_industries_network_camera_consolidation.sc", "gb_riverbed_steelcentral_version.sc", "gb_riverbed_steelhead_ssh_detect.sc", "gb_riverbed_steelhead_http_detect.sc", "gb_dell_sonicwall_sma_sra_consolidation.sc", "gb_dell_sonicwall_gms_detection.sc", "gb_grandstream_ucm_consolidation.sc", "gb_grandstream_gxp_consolidation.sc", "gb_moxa_edr_devices_web_detect.sc", "gb_moxa_iologik_devices_consolidation.sc", "gb_moxa_mgate_consolidation.sc", "gb_moxa_nport_consolidation.sc", "gb_cambium_cnpilot_consolidation.sc", "gb_westermo_weos_detect.sc", "gb_windows_cpe_detect.sc", "gb_huawei_ibmc_consolidation.sc", "gb_huawei_VP9660_mcu_detect.sc", "gb_huawei_home_gateway_http_detect.sc", "gb_avtech_avc7xx_dvr_device_detect.sc", "gb_avtech_device_detect.sc", "gather-package-list.sc", "gb_huawei_euleros_consolidation.sc", "gb_cisco_pis_version.sc", "gb_checkpoint_fw_version.sc", "gb_smb_windows_detect.sc", "gb_nec_communication_platforms_detect.sc", "gb_inim_smartlan_consolidation.sc", "gb_dsx_comm_devices_detect.sc", "gb_vmware_vrealize_operations_manager_web_detect.sc", "gb_ssh_os_detection.sc", "gb_openvpn_access_server_consolidation.sc", "gb_accellion_fta_detect.sc", "gb_proxmox_ve_consolidation.sc", "gb_cisco_smi_detect.sc", "gb_pulse_connect_secure_consolidation.sc", "gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.sc", "gb_citrix_netscaler_version.sc", "gb_intel_standard_manageability_detect.sc", "gb_cisco_ucs_director_consolidation.sc", "gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.sc", "gb_junos_snmp_version.sc", "gb_huawei_vrp_network_device_consolidation.sc", "gb_snmp_os_detection.sc", "gb_dns_os_detection.sc", "gb_ftp_os_detection.sc", "smb_nativelanman.sc", "gb_ucs_detect.sc", "gb_cwp_http_detect.sc", "sw_http_os_detection.sc", "sw_mail_os_detection.sc", "sw_telnet_os_detection.sc", "gb_mysql_mariadb_os_detection.sc", "apcnisd_detect.sc", "gb_dahua_devices_detect.sc", "gb_pptp_os_detection.sc", "gb_f5_enterprise_manager_http_detect.sc", "gb_f5_enterprise_manager_ssh_login_detect.sc", "gb_ntp_os_detection.sc", "remote-detect-MDNS.sc", "mssqlserver_detect.sc", "gb_apple_tv_version.sc", "gb_apple_tv_detect.sc", "gb_upnp_os_detection.sc", "gb_sip_os_detection.sc", "gb_check_mk_agent_detect.sc", "ms_rdp_detect.sc", "gb_schneider_clearscada_detect.sc", "dcetest.sc", "gb_fsecure_internet_gatekeeper_http_detect.sc", "secpod_ocs_inventory_ng_detect.sc", "gb_hnap_os_detection.sc", "gb_ident_os_detection.sc", "gb_pi-hole_detect.sc", "gb_citrix_xenmobile_detect.sc", "gb_dnsmasq_consolidation.sc", "gb_dropbear_consolidation.sc", "gb_monit_detect.sc", "gb_rtsp_os_detection.sc", "gb_nntp_os_detection.sc", "gb_siemens_sinema_server_detect.sc", "gb_owa_detect.sc", "gb_openvas_manager_detect.sc", "gb_gsa_detect.sc", "gb_aerospike_consolidation.sc", "gb_artica_detect.sc", "gb_microfocus_filr_consolidation.sc", "gb_altn_mdaemon_consolidation.sc", "gb_elastix_http_detect.sc", "gb_solarwinds_orion_npm_consolidation.sc", "sw_f5_firepass_http_detect.sc", "gb_gate_one_http_detect.sc", "gb_kaseya_vsa_detect.sc", "gb_manageengine_admanager_plus_consolidation.sc", "gb_emc_isilon_insightiq_detect.sc", "gb_android_adb_detect.sc", "netbios_name_get.sc", "gb_nmap_os_detection.sc", "os_fingerprint.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_crestron_airmedia_consolidation.sc", "gsf/gb_synetica_datastream_devices_detect_telnet.sc", "gsf/gb_paloalto_globalprotect_portal_detect.sc", "gsf/gb_cisco_vision_dynamic_signage_director_detect.sc", "gsf/gb_tibco_loglogic_http_detect.sc", "gsf/gb_inea_me-rtu_http_detect.sc", "gsf/gb_fortios_sslvpn_portal_detect.sc", "gsf/gb_mult_vendors_wlan_controller_aps_detection.sc", "gsf/gb_dell_emc_powerconnect_consolidation.sc", "gsf/gb_cisco_ind_http_detect.sc", "gsf/gb_cisco_csm_http_detect.sc", "gsf/gb_silverpeak_appliance_consolidation.sc", "gsf/gb_ewon_flexy_cosy_http_detect.sc", "gsf/gb_f5_big_iq_consolidation.sc", "gsf/gb_optergy_proton_consolidation.sc", "gsf/gb_unitronics_plc_pcom_detect.sc", "gsf/gb_sonicwall_email_security_consolidation.sc", "gsf/gb_ruckus_zonedirector_consolidation.sc", "gsf/gb_honeywell_ip-ak2_http_detect.sc", "gsf/gb_siemens_sppa-t3000_app_server_http_detect.sc", "gsf/gb_timetools_ntp_server_http_detect.sc", "gsf/gb_aruba_switches_consolidation.sc", "gsf/gb_trendmicro_apex_central_consolidation.sc", "gsf/gb_auerswald_compact_sip_detect.sc", "gsf/gb_beckhoff_ads_udp_detect.sc", "gsf/gb_apache_activemq_jms_detect.sc", "gsf/gb_citrix_sharefile_storage_controller_http_detect.sc", "gsf/gb_konicaminolta_printer_consolidation.sc", "gsf/gb_ibm_spectrum_protect_plus_consolidation.sc", "gsf/gb_nimbus_os_detection.sc", "gsf/gb_secomea_gatemanager_http_detect.sc", "gsf/gb_symantec_endpoint_protection_manager_http_detect.sc", "gsf/gb_vxworks_consolidation.sc", "gsf/gb_spinetix_player_http_detect.sc", "gsf/gb_spinetix_fusion_http_detect.sc", "gsf/gb_mobileiron_core_http_detect.sc", "gsf/gb_mobileiron_sentry_http_detect.sc", "gsf/gb_bigbluebutton_http_detect.sc", "gsf/gb_observium_http_detect.sc", "gsf/gb_ruckus_iot_controller_http_detect.sc", "gsf/gb_contiki_os_http_detect.sc", "gsf/gb_ethernut_http_detect.sc", "gsf/gb_solarwinds_orion_platform_consolidation.sc", "gsf/gb_ui_edgepower_consolidation.sc", "gsf/gb_zyxel_usg_consolidation.sc", "gsf/gb_cisco_dna_center_http_detect.sc", "gsf/gb_magicflow_msa_gateway_http_detect.sc", "gsf/gb_cisco_smart_software_manager_on_prem_http_detect.sc", "gsf/gb_apache_druid_http_detect.sc", "gsf/gb_abb_ac500_opcua_detect.sc", "gsf/gb_netmotion_mobility_server_http_detect.sc", "gsf/gb_samsung_wlan_ap_http_detect.sc", "gsf/gb_cisco_sdwan_vmanage_consolidation.sc", "gsf/gb_schneider_powerlogic_consolidation.sc", "gsf/gb_nexusdb_http_detect.sc", "gsf/gb_fortilogger_http_detect.sc", "gsf/gb_yealink_device_management_http_detect.sc", "gsf/gb_inspur_clusterengine_http_detect.sc", "gsf/gb_passbolt_consolidation.sc", "gsf/gb_vmware_view_planner_http_detect.sc", "gsf/gb_netapp_cloud_manager_http_detect.sc", "gsf/gb_vmware_workspace_one_access_http_detect.sc", "gsf/gb_cisco_meraki_http_detect.sc", "gsf/gb_clickstudios_passwordstate_consolidation.sc", "gsf/gb_kemp_loadmaster_consolidation.sc", "gsf/gb_voipmonitor_http_detect.sc", "gsf/gb_ivanti_avalanche_http_detect.sc", "gsf/gb_vmware_workspace_one_access_http_detect.sc", "gsf/gb_blackberry_uem_http_detect.sc", "gsf/gb_flir_ax8_consolidation.sc", "gsf/gb_flir_a3xx_series_consolidation.sc", "gsf/gb_flir_neco_platform_ssh_login_detect.sc", "gsf/gb_cisco_hyperflex_data_platform_http_detect.sc", "gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.sc", "gsf/gb_tg8_firewall_http_detect.sc", "gsf/gb_maipu_network_device_http_detect.sc", "gsf/gb_cisco_sdwan_vedge_ssh_login_detect.sc", "gsf/gb_akkadian_provisioning_manager_http_detect.sc", "gsf/gb_circontrol_circarlife_http_detect.sc", "gsf/gb_circontrol_raption_http_detect.sc", "gsf/gb_sonicwall_nsm_http_detect.sc", "gsf/gb_dell_wyse_management_suite_http_detect.sc", "gsf/gb_philips_vue_pacs_http_detect.sc", "gsf/gb_philips_vue_motion_http_detect.sc", "gsf/gb_aruba_instant_http_detect.sc", "gsf/gb_elastic_cloud_enterprise_http_detect.sc", "gsf/gb_aapanel_http_detect.sc", "gsf/gb_ruijie_devices_http_detect.sc", "gsf/gb_cisco_firepower_device_manager_http_detect.sc", "gsf/gb_manageengine_adselfservice_plus_http_detect.sc", "gsf/gb_fatpipe_http_detect.sc" );
	}
	script_xref( name: "URL", value: "https://community.greenbone.net/c/vulnerability-tests" );
	script_tag( name: "summary", value: "This script consolidates the OS information detected by several
  VTs and tries to find the best matching OS.

  Furthermore it reports all previously collected information leading to this best matching OS. It
  also reports possible additional information which might help to improve the OS detection.

  If any of this information is wrong or could be improved please consider to report these to the
  referenced community portal." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
found_best = FALSE;
found_os = "";
oid_list = os_get_cpe_src_list();
for oid in oid_list {
	os = get_kb_list( "HostDetails/NVT/" + oid + "/OS" );
	if(!isnull( os )){
		res = make_list( os );
		for entry in res {
			if(!ContainsString( entry, "cpe:/" )){
				continue;
			}
			desc = get_kb_item( "HostDetails/NVT/" + oid );
			if( !found_best ){
				os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
				if(!os_reports){
					continue;
				}
				for key in keys( os_reports ) {
					tmp = split( buffer: key, sep: "/", keep: FALSE );
					port = tmp[3];
					proto = tmp[4];
					os_reports = get_kb_list( key );
					for os_report in os_reports {
						if( !found_best ){
							report = "Best matching OS:\n\n" + os_report;
							found_best = TRUE;
							best_match_oid = oid;
							best_match_desc = desc;
							best_match_report = os_report;
							_best_match_txt = egrep( string: os_report, pattern: "^OS: *[^\r\n]+", icase: FALSE );
							_best_match_txt = chomp( _best_match_txt );
							if( _best_match_txt ){
								_best_match_txt = eregmatch( string: _best_match_txt, pattern: "OS: *(.+)", icase: FALSE );
								if(_best_match_txt[1]){
									best_match_txt = _best_match_txt[1];
									_best_match_txt_vers = egrep( string: os_report, pattern: "^Version: *[^\r\n]+", icase: FALSE );
									_best_match_txt_vers = chomp( _best_match_txt_vers );
									if(_best_match_txt_vers && !IsMatchRegexp( _best_match_txt_vers, "unknown" )){
										_best_match_txt_vers = eregmatch( string: _best_match_txt_vers, pattern: "Version: *(.+)", icase: FALSE );
										if(_best_match_txt_vers[1] && !ContainsString( best_match_txt, _best_match_txt_vers[1] )){
											best_match_txt += " " + _best_match_txt_vers[1];
										}
									}
								}
							}
							else {
								best_match_txt = "N/A";
							}
							_best_match_cpe = egrep( string: os_report, pattern: "^CPE: *[^\r\n]+", icase: FALSE );
							_best_match_cpe = chomp( _best_match_cpe );
							if( _best_match_cpe ){
								_best_match_cpe = eregmatch( string: _best_match_cpe, pattern: "CPE: *(.+)", icase: FALSE );
								if(_best_match_cpe[1]){
									best_match_cpe = _best_match_cpe[1];
								}
							}
							else {
								best_match_cpe = "N/A";
							}
							host_runs_list = get_kb_list( "os_detection_report/host_runs/" + oid + "/" + port + "/" + proto );
							for host_runs in host_runs_list {
								if( host_runs == "unixoide" ){
									set_key = "Host/runs_unixoide";
								}
								else {
									if( host_runs == "windows" ){
										set_key = "Host/runs_windows";
									}
									else {
										set_key = "Host/runs_unixoide";
									}
								}
								if(!get_kb_item( set_key )){
									set_kb_item( name: set_key, value: TRUE );
									report += "\nSetting key \"" + set_key + "\" based on this information";
								}
							}
						}
						else {
							if(!ContainsString( found_os, os_report ) && !ContainsString( best_match_report, os_report )){
								found_os += os_report + "\n\n";
							}
						}
					}
				}
			}
			else {
				os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
				for os_report in os_reports {
					if(!ContainsString( found_os, os_report ) && !ContainsString( best_match_report, os_report )){
						found_os += os_report + "\n\n";
					}
				}
			}
		}
	}
}
if( !found_best ){
	report += "No Best matching OS identified. Please see the VT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
	report += "for possible ways to identify this OS.";
	set_kb_item( name: "Host/runs_unixoide", value: TRUE );
}
else {
	detail = best_match_oid + ";" + best_match_desc;
	set_kb_item( name: "HostDetails/OS/BestMatchCPE", value: best_match_cpe );
	set_kb_item( name: "HostDetails/OS/BestMatchCPE/Details", value: detail );
	set_kb_item( name: "HostDetails/OS/BestMatchTXT", value: best_match_txt );
	set_kb_item( name: "HostDetails/OS/BestMatchTXT/Details", value: detail );
	register_host_detail( name: "OS-Detection", value: best_match_cpe );
	register_host_detail( name: best_match_cpe, value: "general/tcp" );
	register_host_detail( name: "port", value: "general/tcp" );
}
if(found_os){
	report += "\n\nOther OS detections (in order of reliability):\n\n" + found_os;
}
log_message( port: 0, data: report );
exit( 0 );

