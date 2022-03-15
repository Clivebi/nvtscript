if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108094" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_cve_id( "CVE-2012-4929", "CVE-2012-4930" );
	script_bugtraq_id( 55704, 55707 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-03-09 16:00:00 +0100 (Thu, 09 Mar 2017)" );
	script_name( "SSL/TLS: TLS/SPDY Protocol Information Disclosure Vulnerability (CRIME)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "gb_tls_version_get.sc", "gb_tls_npn_alpn_detect.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "ssl_tls/port" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55704" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55707" );
	script_xref( name: "URL", value: "http://permalink.gmane.org/gmane.comp.lib.qt.devel/6729" );
	script_xref( name: "URL", value: "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2012/september/details-on-the-crime-attack/" );
	script_tag( name: "summary", value: "The TLS/SPDY protocols are prone to an information-disclosure vulnerability." );
	script_tag( name: "solution", value: "Disable TLS compression in the configuration of this services. If SPDY below 4 is used upgrade
  the webserver to a version which supports the successor protocol SPDY/4 or HTTP/2.

  Please see the references for more resources supporting you with this task." );
	script_tag( name: "impact", value: "A man-in-the-middle attacker can exploit this issue to gain access to
  sensitive information that may aid in further attacks." );
	script_tag( name: "affected", value: "Services enabling TLS compression or supporting the SPDY protocol below SPDY/4 via HTTPS." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("mysql.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("byte_func.inc.sc");
require("ssl_funcs.inc.sc");
comp_report = "The remote service might be vulnerable to the \"CRIME\" attack because it provides the following TLS compression methods:\n\nProtocol:Compression Method\n";
npn_report = "The remote service might be vulnerable to the \"CRIME\" attack because it advertises support for the following vulnerable Network Protocol(s) via the NPN extension:\n\nSSL/TLS Protocol:Network Protocol\n";
alpn_report = "The remote service might be vulnerable to the \"CRIME\" attack because it advertises support for the following vulnerable Network Protocol(s) via the ALPN extension:\n\nSSL/TLS Protocol:Network Protocol\n";
port = http_get_port( default: 443, ignore_broken: TRUE, ignore_cgi_disabled: TRUE );
if(get_port_transport( port ) < ENCAPS_SSLv23){
	exit( 0 );
}
if(!versions = get_supported_tls_versions( port: port, min: SSL_v3 )){
	exit( 0 );
}
for version in versions {
	if(version == TLS_13){
		continue;
	}
	for compression_method in make_list( "DEFLATE",
		 "LZS" ) {
		hello_done = FALSE;
		soc = open_ssl_socket( port: port );
		if(!soc){
			continue;
		}
		hello = ssl_hello( port: port, version: version, compression_method: compression_method );
		if(!hello){
			close( soc );
			continue;
		}
		send( socket: soc, data: hello );
		for(;!hello_done;){
			data = ssl_recv( socket: soc );
			if(!data){
				close( soc );
				break;
			}
			record = search_ssl_record( data: data, search: make_array( "content_typ", SSLv3_ALERT ) );
			if(record){
				close( soc );
				break;
			}
			record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
			if(record){
				if(record["compression_method"] == ord( compression_methods[compression_method] )){
					comp_vuln = TRUE;
					comp_report += version_string[version] + ":" + compression_method + "\n";
				}
			}
			record = search_ssl_record( data: data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
			if(record){
				hello_done = TRUE;
				break;
			}
		}
	}
}
for version in versions {
	if(!SSL_VER = version_kb_string_mapping[version]){
		continue;
	}
	npn_prot_list = get_kb_list( "tls_npn_prot_supported/" + SSL_VER + "/" + port );
	for npn_prot in npn_prot_list {
		if(IsMatchRegexp( npn_prot, "spdy/[1-3]" )){
			npn_vuln = TRUE;
			npn_report += version_string[version] + ":" + npn_alpn_name_mapping[npn_prot] + "\n";
		}
	}
	alpn_prot_list = get_kb_list( "tls_alpn_prot_supported/" + SSL_VER + "/" + port );
	for alpn_prot in alpn_prot_list {
		if(IsMatchRegexp( alpn_prot, "spdy/[1-3]" )){
			alpn_vuln = TRUE;
			alpn_report += version_string[version] + ":" + npn_alpn_name_mapping[alpn_prot] + "\n";
		}
	}
}
if(comp_vuln || npn_vuln || alpn_vuln){
	if(comp_vuln){
		report += comp_report;
	}
	if(npn_vuln){
		report += "\n" + npn_report;
	}
	if(alpn_vuln){
		report += "\n" + alpn_report;
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

