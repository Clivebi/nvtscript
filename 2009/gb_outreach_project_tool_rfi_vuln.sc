if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801070" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4082" );
	script_bugtraq_id( 37090 );
	script_name( "Outreach Project Tool 'CRM_path' Parameter Remote File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37447" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54379" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/0911-exploits/opt-rfi.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_outreach_project_tool_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "outreach_project_tool/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow the remote attackers to include
  arbitrary files from local and remote resources to compromise a vulnerable server." );
	script_tag( name: "affected", value: "Outreach Project Tool(OPT) version 1.2.7 and prior." );
	script_tag( name: "insight", value: "Error is due to improper sanitization of user supplied input in
  'CRM_path' parameter in 'opt/forums/Forum_Include/index.php' while including external files for processing." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Outreach Project Tool(OPT) and is prone to
  Remote File Inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
optPort = http_get_port( default: 80 );
optVer = get_kb_item( "www/" + optPort + "/OPT" );
if(!optVer){
	exit( 0 );
}
optVer = eregmatch( pattern: "^(.+) under (/.*)$", string: optVer );
if(!safe_checks() && optVer[2] != NULL){
	request = http_get( item: optVer[2] + "/forums/Forum_Include/index.php?" + "CRM_path=vt-rfi.txt", port: optPort );
	response = http_send_recv( port: optPort, data: request );
	if(ContainsString( response, "vt-rfi.txt" )){
		security_message( optPort );
		exit( 0 );
	}
}
if(optVer[1] != NULL){
	if(version_is_less_equal( version: optVer[1], test_version: "1.2.7" )){
		security_message( optPort );
	}
}

