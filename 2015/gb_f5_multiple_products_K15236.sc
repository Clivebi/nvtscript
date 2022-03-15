if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105172" );
	script_bugtraq_id( 69461 );
	script_cve_id( "CVE-2014-2927" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-05-07T11:32:46+0000" );
	script_name( "Multiple F5 Networks Products - ConfigSync IP Rsync full file system access vulnerability CVE-2014-2927 - Active Check" );
	script_tag( name: "last_modification", value: "2021-05-07 11:32:46 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2015-01-19 11:51:31 +0100 (Mon, 19 Jan 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Gain a shell remotely" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "rsync_modules.sc" );
	script_require_ports( "Services/rsync", 873 );
	script_mandatory_keys( "rsync/modules_in_kb" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/69461" );
	script_xref( name: "URL", value: "https://support.f5.com/csp/article/K15236" );
	script_tag( name: "summary", value: "Multiple F5 Networks Products are prone to a remote
  code-execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to read the /VERSION file via a rsync request." );
	script_tag( name: "insight", value: "An open Rsync configuration for the ConfigSync IP address allows
  for remote read/write file system access." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code
  within the context of the application." );
	script_tag( name: "affected", value: "F5 BIG-IP 11.6 before 11.6.0, 11.5.1 before HF3, 11.5.0 before
  HF4, 11.4.1 before HF4, 11.4.0 before HF7, 11.3.0 before HF9, and 11.2.1 before HF11.

  Enterprise Manager 3.x before 3.1.1 HF2." );
	script_tag( name: "solution", value: "Disable the rsync daemon or update to a fixed version listed at
  the referenced vendor advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("string_hex_func.inc.sc");
require("port_service_func.inc.sc");
require("byte_func.inc.sc");
require("rsync_func.inc.sc");
port = rsync_get_port( default: 873 );
if(!modules = get_kb_item( "rsync/" + port + "/modules" )){
	exit( 0 );
}
if( ContainsString( modules, "csync" ) ){
	module = "csync";
}
else {
	if(ContainsString( modules, "cmi" )){
		module = "cmi";
	}
}
if(!module){
	exit( 0 );
}
if(!soc = rsync_connect( port: port )){
	exit( 0 );
}
buf = rsync_get_file( soc: soc, module: module, file: "VERSION" );
close( soc );
if(ContainsString( buf, "Product: BIG-IQ" ) || ContainsString( buf, "Product: BIG-IP" ) || ContainsString( buf, "Product: EM" )){
	report = "It was possible to download the VERSION file from the remote host via the " + module + " module:\n\n" + buf;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

