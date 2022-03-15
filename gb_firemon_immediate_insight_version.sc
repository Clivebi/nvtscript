if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140107" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-29 10:07:33 +0100 (Thu, 29 Dec 2016)" );
	script_name( "FireMon Immediate Insight Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of FireMon Immediate Insight" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success", "firemon/immediate_insight/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
if(!port = kb_ssh_transport()){
	exit( 0 );
}
if(!sock = ssh_login_or_reuse_connection()){
	exit( 0 );
}
buf = ssh_cmd( socket: sock, cmd: "PATH=/home/insight/app/utils/:$PATH /home/insight/app/utils/status" );
close( sock );
if(!ContainsString( buf, "Immediate Insight" )){
	exit( 0 );
}
set_kb_item( name: "firemon/immediate_insight/status", value: buf );
cpe = "cpe:/a:firemon:immediate_insight";
version = "unknown";
lines = split( buf );
for line in lines {
	if(IsMatchRegexp( line, "Immediate Insight.* version: " )){
		v = eregmatch( pattern: "Immediate Insight.* version: ([^\r\n]+)", string: line );
		break;
	}
}
if(!isnull( v[1] )){
	version = v[1];
	cpe += ":" + version;
	set_kb_item( name: "firemon/immediate_insight/version", value: version );
}
register_product( cpe: cpe, location: "ssh", port: port, service: "ssh" );
report = build_detection_report( app: "FireMon Immediate Insight", version: version, install: "ssh", cpe: cpe, concluded: v[0] );
log_message( port: port, data: report );
exit( 0 );

