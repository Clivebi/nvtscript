if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900817" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_name( "Sun/Oracle OpenSSO Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Sun/Oracle OpenSSO.
  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in make_list( "/",
	 "/opensso",
	 "/sso" ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/UI/Login.jsp", port: port );
	if(ContainsString( res, "OpenSSO" ) && ContainsString( res, "X-DSAMEVersion" ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: res )){
		cpe = "cpe:/a:oracle:opensso";
		version = "unknown";
		set_kb_item( name: "Oracle/OpenSSO/detected", value: TRUE );
		set_kb_item( name: "JavaSysAccessManger_or_OracleOpenSSO/detected", value: TRUE );
		vers = eregmatch( pattern: "X-DSAMEVersion:( Enterprise | Snapshot Build | Oracle OpenSSO )?([0-9]\\.[0-9.]+([a-zA-Z0-9 ]+)?)", string: res );
		if(!isnull( vers[2] )){
			concluded = vers[0];
			version = ereg_replace( pattern: " ", string: vers[2], replace: "." );
			cpe += ":" + version;
			tmp_version = version + " under " + install;
			set_kb_item( name: "www/" + port + "/Sun/OpenSSO", value: tmp_version );
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Sun/Oracle OpenSSO", version: version, install: install, cpe: cpe, concluded: concluded ), port: port );
		exit( 0 );
	}
}
exit( 0 );

