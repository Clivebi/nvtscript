if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17342" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "TFTP file detection (Cisco IOS)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Corsaire Limited." );
	script_family( "Remote file access" );
	script_dependencies( "tftpd_detect.sc", "tftpd_backdoor.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "solution", value: "If it is not required, disable the TFTP server. Otherwise
  restrict access to trusted sources only." );
	script_tag( name: "summary", value: "The remote host has a TFTP server installed that is serving one or
  more sensitive Cisco IOS files." );
	script_tag( name: "insight", value: "These files potentially include
  passwords and other sensitive information, so should not be exposed to unnecessary scrutiny." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("tftp.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
if(!tftp_has_reliable_get( port: port )){
	exit( 0 );
}
file_list = make_list( "startup-config",
	 "network-confg",
	 "network.cfg",
	 "network.confg",
	 "cisconet-confg",
	 "cisconet.cfg",
	 "cisconet.confg",
	 "router-confg",
	 "router.config",
	 "router.cfg",
	 "ciscortr-confg",
	 "ciscortr.config",
	 "ciscortr.cfg",
	 "cisco-confg",
	 "cisco.confg",
	 "cisco.cfg" );
for file_name in file_list {
	if(tftp_get( port: port, path: file_name )){
		detected_files += file_name + "\n";
	}
}
if(detected_files){
	report = "The filenames detected are:\n\n" + detected_files;
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
exit( 99 );

