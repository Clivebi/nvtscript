if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103997" );
	script_version( "2021-04-15T10:25:32+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 10:25:32 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-16 12:21:12 +0100 (Wed, 16 Mar 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Host Details" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_category( ACT_END );
	script_dependencies( "gb_wmi_get-dns_name.sc", "netbios_name_get.sc", "sw_ssl_cert_get_hostname.sc", "gb_host_id_tag_ssh.sc", "host_scan_end.sc", "gb_tls_version.sc", "gb_hostname_determ_reporting.sc" );
	script_tag( name: "summary", value: "This scripts aggregates the OS detection information gathered by
  several VTs and store it in a structured and unified way." );
	script_tag( name: "qod_type", value: "remote_probe" );
	script_timeout( 3600 );
	exit( 0 );
}
SCRIPT_DESC = "Host Details";
require("xml.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
hostname = get_host_name();
hostip = get_host_ip();
if(!isnull( hostname ) && hostname != "" && hostname != hostip){
	register_host_detail( name: "hostname", value: hostname, desc: SCRIPT_DESC );
}
if(hostname == hostip || hostname == "" || isnull( hostname )){
	DNS_via_WMI_FQDNS = get_kb_item( "DNS-via-WMI-FQDNS" );
	if( !isnull( DNS_via_WMI_FQDNS ) && DNS_via_WMI_FQDNS != "" && DNS_via_WMI_FQDNS != hostip ){
		register_host_detail( name: "hostname", value: DNS_via_WMI_FQDNS, desc: SCRIPT_DESC );
	}
	else {
		DNS_via_WMI_DNS = get_kb_item( "DNS-via-WMI-DNS" );
		if( !isnull( DNS_via_WMI_DNS ) && DNS_via_WMI_DNS != "" && DNS_via_WMI_DNS != hostip ){
			register_host_detail( name: "hostname", value: DNS_via_WMI_DNS, desc: SCRIPT_DESC );
		}
		else {
			SMB_HOST_NAME = get_kb_item( "SMB/name" );
			if( !isnull( SMB_HOST_NAME ) && SMB_HOST_NAME != "" && SMB_HOST_NAME != hostip ){
				register_host_detail( name: "hostname", value: SMB_HOST_NAME, desc: SCRIPT_DESC );
			}
			else {
				DNS_via_SSL_TLS_Cert_List = get_kb_list( "DNS_via_SSL_TLS_Cert" );
				for DNS_via_SSL_TLS_Cert in DNS_via_SSL_TLS_Cert_List {
					if(DNS_via_SSL_TLS_Cert != "" && DNS_via_SSL_TLS_Cert != hostip){
						register_host_detail( name: "hostname", value: DNS_via_SSL_TLS_Cert, desc: SCRIPT_DESC );
						break;
					}
				}
			}
		}
	}
}
report_host_details = get_preference( "report_host_details" );
if(report_host_details && ContainsString( report_host_details, "yes" )){
	report_host_details();
}
exit( 0 );

