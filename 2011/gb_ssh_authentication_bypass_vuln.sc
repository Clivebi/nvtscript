if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801993" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)" );
	script_cve_id( "CVE-2001-0361", "CVE-2001-0572", "CVE-2001-1473" );
	script_bugtraq_id( 2344 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Deprecated SSH-1 Protocol Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ssh_proto_version.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "SSH/supportedversions/available" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/684820" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/6603" );
	script_tag( name: "impact", value: "Successful exploitation could allows remote attackers to bypass security
  restrictions and to obtain a client's public host key during a connection attempt and use it to open and
  authenticate an SSH session to another server with the same access." );
	script_tag( name: "affected", value: "Services providing / accepting the SSH protocol version SSH-1 (1.33 and 1.5)." );
	script_tag( name: "solution", value: "Reconfigure the SSH service to only provide / accept the SSH protocol version SSH-2." );
	script_tag( name: "summary", value: "The host is running SSH and is providing / accepting one or more deprecated versions
  of the SSH protocol which have known cryptograhic flaws." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
versions = get_kb_list( "SSH/supportedversions/" + port );
if(!versions){
	exit( 0 );
}
versions = sort( versions );
report = "The service is providing / accepting the following deprecated versions of the SSH protocol which have known cryptograhic flaws:\n";
for version in versions {
	if(version == "1.33" || version == "1.5"){
		report += "\n" + version;
		VULN = TRUE;
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

