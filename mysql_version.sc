if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100152" );
	script_version( "2021-02-12T06:42:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 06:42:15 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2009-04-23 19:21:19 +0000 (Thu, 23 Apr 2009)" );
	script_name( "MariaDB / Oracle MySQL Detection (MySQL Protocol)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service1.sc", "sw_sphinxsearch_detect.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_tag( name: "summary", value: "MySQL protocol-based detection of MariaDB / Oracle MySQL." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("mysql.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("version_func.inc.sc");
set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
port = service_get_port( default: 3306, proto: "mysql" );
if(get_kb_item( "sphinxsearch/" + port + "/detected" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = mysql_recv_server_handshake( socket: soc );
close( soc );
if( ord( buf[0] ) == 255 ){
	errno = ord( buf[2] ) << 8 | ord( buf[1] );
	if(errno == ER_HOST_IS_BLOCKED || errno == ER_HOST_NOT_PRIVILEGED){
		set_kb_item( name: "mysql_mariadb/blocked", value: TRUE );
		set_kb_item( name: "mysql_mariadb/" + port + "/blocked", value: TRUE );
		set_kb_item( name: "MySQL/" + port + "/blocked", value: TRUE );
		if( errno == ER_HOST_IS_BLOCKED ){
			extra = "Scanner received a ER_HOST_IS_BLOCKED ";
			if( ContainsString( buf, "mariadb-admin" ) ){
				MariaDB_FOUND = TRUE;
				extra += "error from the remote MariaDB server.\nSome ";
				extra += "tests may fail. Run 'mariadb-admin flush-hosts' to ";
				extra += "enable scanner access to this host.";
			}
			else {
				if( ContainsString( buf, "mysqladmin" ) ){
					MySQL_FOUND = TRUE;
					extra += "error from the remote MySQL server.\nSome ";
					extra += "tests may fail. Run 'mysqladmin flush-hosts' to ";
					extra += "enable scanner access to this host.";
				}
				else {
					MariaDB_or_MySQL_FOUND = TRUE;
					extra += "error from the remote MySQL/MariaDB server.\nSome ";
					extra += "tests may fail. Run 'mysqladmin flush-hosts' or ";
					extra += "'mariadb-admin flush-hosts' to ";
					extra += "enable scanner access to this host.";
				}
			}
		}
		else {
			if(errno == ER_HOST_NOT_PRIVILEGED){
				extra = "Scanner received a ER_HOST_NOT_PRIVILEGED ";
				if( ContainsString( buf, "MariaDB" ) ){
					MariaDB_FOUND = TRUE;
					extra += "error from the remote MariaDB server.\nSome ";
					extra += "tests may fail. Allow the scanner to access the ";
					extra += "remote MariaDB server for better results.";
				}
				else {
					if( ContainsString( buf, "MySQL" ) ){
						MySQL_FOUND = TRUE;
						extra += "error from the remote MySQL server.\nSome ";
						extra += "tests may fail. Allow the scanner to access the ";
						extra += "remote MySQL server for better results.";
					}
					else {
						MariaDB_or_MySQL_FOUND = TRUE;
						extra += "error from the remote MySQL/MariaDB server.\nSome ";
						extra += "tests may fail. Allow the scanner to access the ";
						extra += "remote MySQL/MariaDB server for better results.";
					}
				}
			}
		}
	}
}
else {
	if(ord( buf[0] ) == 10){
		if( ContainsString( buf, "MariaDB" ) ) {
			MariaDB_FOUND = TRUE;
		}
		else {
			MySQL_FOUND = TRUE;
		}
		for(i = 1;i < strlen( buf );i++){
			if( ord( buf[i] ) != 0 ) {
				version += buf[i];
			}
			else {
				break;
			}
		}
	}
}
if(MySQL_FOUND || MariaDB_or_MySQL_FOUND){
	if( version ){
		concluded = version;
		set_kb_item( name: "mysql_mariadb/full_banner/" + port, value: version );
		set_kb_item( name: "OpenDatabase/found", value: TRUE );
		set_kb_item( name: "oracle/mysql/" + port + "/open_accessible", value: TRUE );
	}
	else {
		version = "unknown";
	}
	set_kb_item( name: "oracle/mysql/detected", value: TRUE );
	set_kb_item( name: "mysql_mariadb/detected", value: TRUE );
	set_kb_item( name: "oracle/mysql/" + port + "/detected", value: TRUE );
	set_kb_item( name: "mysql_mariadb/" + port + "/detected", value: TRUE );
	set_kb_item( name: "MySQL/installed", value: TRUE );
	set_kb_item( name: "MySQL_MariaDB/installed", value: TRUE );
	service_register( port: port, proto: "mysql" );
	cpe1 = build_cpe( value: version, exp: "^([0-9.]+-?[a-zA-Z]+?)", base: "cpe:/a:mysql:mysql:" );
	if(!cpe1){
		cpe1 = "cpe:/a:mysql:mysql";
	}
	cpe2 = build_cpe( value: version, exp: "^([0-9.]+[a-zA-Z]+?)", base: "cpe:/a:oracle:mysql:" );
	if(!cpe2){
		cpe2 = "cpe:/a:oracle:mysql";
	}
	install = port + "/tcp";
	register_product( cpe: cpe1, location: install, port: port, service: "mysql" );
	register_product( cpe: cpe2, location: install, port: port, service: "mysql" );
	log_message( data: build_detection_report( app: "Oracle MySQL", version: version, install: install, cpe: cpe2, concluded: concluded, extra: extra ), port: port );
}
if(MariaDB_FOUND){
	if( version ){
		if( IsMatchRegexp( version, "([0-9.]+)-([0-9.]+)-([A-Za-z]+)?" ) ){
			version = eregmatch( pattern: "([0-9.]+)-([0-9.]+)-", string: version );
			version = version[2];
		}
		else {
			version = eregmatch( pattern: "([0-9.]+)-", string: version );
			version = version[1];
		}
		concluded = egrep( pattern: "([0-9.]+)(-([0-9.]+))?-", string: buf );
		set_kb_item( name: "mysql_mariadb/full_banner/" + port, value: concluded );
		set_kb_item( name: "OpenDatabase/found", value: TRUE );
		set_kb_item( name: "mariadb/" + port + "/open_accessible", value: TRUE );
	}
	else {
		version = "unknown";
	}
	set_kb_item( name: "mariadb/detected", value: TRUE );
	set_kb_item( name: "mysql_mariadb/detected", value: TRUE );
	set_kb_item( name: "mariadb/" + port + "/detected", value: TRUE );
	set_kb_item( name: "mysql_mariadb/" + port + "/detected", value: TRUE );
	set_kb_item( name: "MariaDB/installed", value: TRUE );
	set_kb_item( name: "MySQL_MariaDB/installed", value: TRUE );
	service_register( port: port, proto: "mysql" );
	cpe = build_cpe( value: version, exp: "^([0-9.]+-?[a-zA-Z]+?)", base: "cpe:/a:mariadb:mariadb:" );
	if(!cpe){
		cpe = "cpe:/a:mariadb:mariadb";
	}
	install = port + "/tcp";
	register_product( cpe: cpe, location: install, port: port, service: "mysql" );
	log_message( data: build_detection_report( app: "MariaDB", version: version, install: install, cpe: cpe, concluded: concluded, extra: extra ), port: port );
}
exit( 0 );

