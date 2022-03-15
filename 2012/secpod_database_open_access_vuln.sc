if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902799" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Database Open Access Vulnerability" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc", "gb_ibm_db2_das_detect.sc", "postgresql_detect.sc", "mssqlserver_detect.sc", "gb_ibm_soliddb_detect.sc", "mysql_version.sc", "secpod_open_tcp_ports.sc", "gb_open_udp_ports.sc" );
	script_mandatory_keys( "OpenDatabase/found" );
	script_xref( name: "URL", value: "https://www.pcisecuritystandards.org/security_standards/index.php?id=pci_dss_v1-2.pdf" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to obtain the sensitive
  information of the database." );
	script_tag( name: "insight", value: "Do not restricting direct access of databases to the remote systems." );
	script_tag( name: "summary", value: "The host is running a Database server and is prone to information
  disclosure vulnerability." );
	script_tag( name: "affected", value: "- Oracle MySQL

  - MariaDB

  - IBM DB2

  - PostgreSQL

  - IBM solidDB

  - Oracle Database

  - Microsoft SQL Server" );
	script_tag( name: "solution", value: "Restrict Database access to remote systems." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
func is_oracle_db( port ){
	var port, ver;
	ver = get_kb_item( "oracle_tnslsnr/" + port + "/version" );
	if( ver ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func is_ibm_db2( port ){
	var port, ibmVer;
	ibmVer = get_kb_item( "ibm/db2/das/" + port + "/version" );
	if( ibmVer ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func is_postgre_sql( port ){
	var port, psqlver;
	psqlver = get_kb_item( "PostgreSQL/Remote/" + port + "/Ver" );
	if( psqlver ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func is_solid_db( port ){
	var port, solidVer;
	solidVer = get_kb_item( "soliddb/" + port + "/version" );
	if( solidVer ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func is_mssql( port ){
	var port, mssql_rls;
	mssql_rls = get_kb_item( "MS/SQLSERVER/" + port + "/releasename" );
	if( mssql_rls ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func is_mysql( port ){
	var port, myVer;
	myVer = get_kb_item( "oracle/mysql/" + port + "/open_accessible" );
	if( myVer ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func is_mariadb( port ){
	var port, mariaVer;
	mariaVer = get_kb_item( "mariadb/" + port + "/open_accessible" );
	if( mariaVer ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
ports = tcp_get_all_ports();
ports = nasl_make_list_unique( ports, 5432, 1433, 1315, 3306, 1521 );
for port in ports {
	oracle_db = is_oracle_db( port: port );
	if(oracle_db){
		log_message( data: "Oracle database can be accessed by remote attackers", port: port );
		continue;
	}
	mysql = is_mysql( port: port );
	if(mysql){
		log_message( data: "Oracle MySQL can be accessed by remote attackers", port: port );
		continue;
	}
	mariadb = is_mariadb( port: port );
	if(mariadb){
		log_message( data: "MariaDB can be accessed by remote attackers", port: port );
		continue;
	}
	postgre_sql = is_postgre_sql( port: port );
	if(postgre_sql){
		log_message( data: "PostgreSQL database can be accessed by remote attackers", port: port );
		continue;
	}
	solid_db = is_solid_db( port: port );
	if(solid_db){
		log_message( data: "SolidDB can be accessed by remote attackers", port: port );
		continue;
	}
	mssql = is_mssql();
	if(mssql){
		log_message( data: "Microsoft SQL Server can be accessed by remote attackers", port: port );
		continue;
	}
}
udp_ports = udp_get_all_ports();
udp_ports = nasl_make_list_unique( udp_ports, 523 );
for udp_port in udp_ports {
	ibm_db2 = is_ibm_db2( port: udp_port );
	if(ibm_db2){
		log_message( data: "IBM DB2 can be accessed by remote attackers", port: udp_port, proto: "udp" );
		continue;
	}
}
exit( 0 );

