if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105776" );
	script_version( "2021-07-01T08:13:06+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-01 08:13:06 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-06-22 11:05:14 +0200 (Wed, 22 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Veeam Backup & Replication Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Veeam Backup & Replication" );
	script_xref( name: "URL", value: "https://www.veeam.com/vm-backup-recovery-replication-software.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9443 );
url = "/login.aspx";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "Veeam Backup Enterprise Manager : Login" ) && ( !ContainsString( buf, "Veeam.CredentialsPanel" ) || !ContainsString( buf, "LoginConfig" ) )){
	exit( 0 );
}
cpe = "cpe:/a:veeam:backup_and_replication";
set_kb_item( name: "veeam_backup_and_replication/detected", value: TRUE );
set_kb_item( name: "veeam_backup_and_replication/http/detected", value: TRUE );
version = "unknown";
vers = eregmatch( pattern: "\\.(css|js|ico)\\?v=([0-9.]+[^\"]+)\"", string: buf );
if(!isnull( vers[2] )){
	version = vers[2];
	cpe += ":" + version;
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Veeam Backup & Replication", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

