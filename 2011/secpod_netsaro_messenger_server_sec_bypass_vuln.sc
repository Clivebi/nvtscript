if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902465" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)" );
	script_cve_id( "CVE-2011-3692", "CVE-2011-3693" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "NetSaro Enterprise Messenger Server Plaintext Password Storage Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2011/Aug/94" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519284" );
	script_xref( name: "URL", value: "http://www.solutionary.com/index/SERT/Vuln-Disclosures/NetSaro-Enterprise-Messenger-Vuln-Password.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 4992 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow local attackers to access
  the configuration.xml file. Then can decrypt all username and password
  values and reuse them against other systems within the network." );
	script_tag( name: "affected", value: "NetSaro Enterprise Messenger Server version 2.0 and prior." );
	script_tag( name: "insight", value: "The flaw exists in application because it stores the username
  and password in plain text format, which allows an attacker to easily decrypt
  passwords used to authenticate to the application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running NetSaro Enterprise Messenger Server and is
  prone to security bypass vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 4992 );
rcvRes = http_get_cache( item: "/", port: port );
if(ContainsString( rcvRes, "></NetSaroEnterpriseMessenger>" )){
	netsVer = eregmatch( pattern: "version=\"([0-9.]+)", string: rcvRes );
	if(netsVer[1] != NULL){
		if(version_is_less_equal( version: netsVer[1], test_version: "2.1" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

