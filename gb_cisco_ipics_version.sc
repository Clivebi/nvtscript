if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105601" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-04-11 13:25:26 +0200 (Mon, 11 Apr 2016)" );
	script_name( "Cisco IP Interoperability and Collaboration System Version Detection" );
	script_tag( name: "summary", value: "This Script performs SSH based detection of Cisco IP Interoperability and Collaboration System" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco/ipics/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
if(!get_kb_item( "cisco/ipics/detected" )){
	exit( 0 );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
ipics_version = ssh_cmd( socket: sock, cmd: "/opt/cisco/ipics/bin/versions" );
close( sock );
if(!ContainsString( ipics_version, "UMS" )){
	exit( 0 );
}
set_kb_item( name: "cisco/ipics/ipics_bin_versions", value: ipics_version );
vers = "unknown";
cpe = "cpe:/a:cisco:ip_interoperability_and_collaboration_system";
version = eregmatch( pattern: "UMS\\s*[\r\n]+[-]+[\r\n]+Version\\s*\\(RPM\\):\\s*([0-9]+[^\r\n]+)", string: ipics_version );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "cisco/ipics/version", value: vers );
}
register_product( cpe: cpe, location: "ssh" );
report = build_detection_report( app: "Cisco IP Interoperability and Collaboration System", version: vers, install: "ssh", cpe: cpe, concluded: version[0] );
log_message( port: 0, data: report );
exit( 0 );

