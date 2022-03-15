if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14227" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 7549 );
	script_cve_id( "CVE-2003-0286" );
	script_xref( name: "OSVDB", value: "4638" );
	script_name( "Snitz Forums 2000 SQL injection" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_dependencies( "snitz_forums_2000_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "snitzforums/detected" );
	script_tag( name: "summary", value: "The remote host is using Snitz Forum 2000 which allows an attacker
  to execute stored procedures and non-interactive operating system commands on the system." );
	script_tag( name: "insight", value: "The problem stems from the fact that the 'Email' variable
  in the register.asp module fails to properly validate and strip out malicious SQL data." );
	script_tag( name: "impact", value: "An attacker, exploiting this flaw, would need network access
  to the webserver. A successful attack would allow the remote attacker the ability to potentially
  execute arbitrary system commands through common SQL stored procedures such as xp_cmdshell." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/SnitzForums" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(egrep( string: vers, pattern: "^([0-2]\\.*|3\\.[0-2]\\.*|3\\.3\\.0[0-2])" )){
		security_message( port );
		exit( 0 );
	}
}
