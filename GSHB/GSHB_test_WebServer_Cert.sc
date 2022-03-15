if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96057" );
	script_version( "$Revision: 10611 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 13:49:26 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Test Webserver SSL Certificate" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_add_preference( name: "X.509 Root Authority Certificate(PEM)", type: "file", value: "" );
	script_tag( name: "summary", value: "This plugin uses openssl to verify TLS/SSL Certificates." );
	exit( 0 );
}
if( get_kb_item( "Ports/tcp/443" ) ) {
	port = 443;
}
else {
	set_kb_item( name: "GSHB/SSL-Cert", value: "none" );
	exit( 0 );
}
RootPEM = script_get_preference_file_content( "X.509 Root Authority Certificate(PEM)" );
temp = get_tmp_dir();
ip = get_host_ip();
fwrite( file: temp + ip + "-GSHB_RootPEM.pem", data: RootPEM );
p = 0;
argv[p++] = "openssl";
argv[p++] = "verify";
argv[p++] = temp + ip + "-GSHB_RootPEM.pem";
RootPEMstate = pread( cmd: "openssl", argv: argv, cd: 5 );
if( IsMatchRegexp( RootPEMstate, ".*-GSHB_RootPEM.pem: OK.*" ) ){
	i = 0;
	argv[i++] = "openssl";
	argv[i++] = "s_client";
	argv[i++] = "-CAfile";
	argv[i++] = temp + ip + "-GSHB_RootPEM.pem";
	argv[i++] = "-connect";
	argv[i++] = ip + ":" + port;
	sslcert = pread( cmd: "openssl", argv: argv, cd: 5 );
	RootPEMstate = "OK";
}
else {
	i = 0;
	argv[i++] = "openssl";
	argv[i++] = "s_client";
	argv[i++] = "-connect";
	argv[i++] = ip + ":" + port;
	sslcert = pread( cmd: "openssl", argv: argv, cd: 5 );
	RootPEMstate = "FAIL";
}
if( !ContainsString( sslcert, "unknown protocol" ) ){
	subject = egrep( string: sslcert, pattern: "subject=.*" );
	rtcode = egrep( string: sslcert, pattern: "Verify return code:.*" );
	certresult = subject + rtcode;
}
else {
	certresult = "unknown";
	log_message( port: 0, proto: "IT-Grundschutz", data: sslcert );
}
unlink( temp + ip + "-GSHB_RootPEM.pem" );
set_kb_item( name: "GSHB/SSL-Cert", value: certresult );
set_kb_item( name: "GSHB/SSL-Cert/RootPEMstate", value: RootPEMstate );
exit( 0 );

