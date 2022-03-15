if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106237" );
	script_version( "2021-09-24T07:45:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:45:50 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-09 11:33:30 +0700 (Fri, 09 Sep 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "SSL/TLS: Certificate In Chain Expired" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "gb_ssl_tls_cert_chain_get.sc" );
	script_mandatory_keys( "ssl_tls/port", "ssl_tls/cert_chain/extracted" );
	script_tag( name: "summary", value: "The remote service is using a SSL/TLS certificate chain where
  one or multiple CA certificates have expired." );
	script_tag( name: "vuldetect", value: "Checks the expire date of the CA certificates." );
	script_tag( name: "insight", value: "Checks if the CA certificates in the SSL/TLS certificate chain
  have expired." );
	script_tag( name: "solution", value: "Sign your server certificate with a valid CA certificate." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("misc_func.inc.sc");
require("ssl_funcs.inc.sc");
func check_validity( port, now ){
	if(!port){
		return;
	}
	expired = make_list();
	if(!c = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/chain" )){
		exit( 0 );
	}
	for f in c {
		f = base64_decode( str: f );
		if(!certobj = cert_open( f )){
			continue;
		}
		expire_date = cert_query( certobj, "not-after" );
		if(expire_date < now){
			subject = cert_query( certobj, "subject" );
			expired = make_list( expired,
				 subject + ">##<" + expire_date );
		}
		cert_close( certobj );
	}
	if(max_index( expired ) > 0){
		return expired;
	}
	return;
}
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
now = isotime_now();
if(strlen( now ) <= 0){
	exit( 0 );
}
if(ret = check_validity( port: port, now: now )){
	for a in ret {
		exp = split( buffer: a, sep: ">##<", keep: FALSE );
		subj = exp[0];
		exp_date = exp[1];
		report_expired += "Subject:     " + subj + "\nExpired on:  " + isotime_print( exp_date ) + "\n\n";
	}
	report = "The following certificates which are part of the certificate chain have expired:\n\n" + report_expired;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

