if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103692" );
	script_version( "2021-10-01T07:04:12+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 07:04:12 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2013-04-09 14:14:14 +0200 (Tue, 09 Apr 2013)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSL/TLS: Collect and Report Certificate Details" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "secpod_ssl_ciphers.sc", "gb_ssl_sni_supported.sc" );
	script_mandatory_keys( "ssl_tls/port" );
	script_tag( name: "summary", value: "This script collects and reports the details of all SSL/TLS
  certificates.

  This data will be used by other tests to verify server certificates." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("global_settings.inc.sc");
require("misc_func.inc.sc");
require("ssl_funcs.inc.sc");
require("byte_func.inc.sc");
require("mysql.inc.sc");
require("xml.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
func read_and_parse_certs( cert, port ){
	var cert, port;
	var certobj, idx, tmp, fpr, prefix, hostnames, item;
	if(!cert){
		return;
	}
	certobj = cert_open( cert );
	if(!certobj){
		set_kb_item( name: "HostDetails/SSLInfo/" + port, value: "[ERROR]" );
		log_message( data: "The certificate of the remote service cannot be parsed!", port: port );
		return;
	}
	if(log_verbosity > 1){
		debug_print( "SSL certificate on port ", port, ":\\n" );
		debug_print( "serial ..........: ", cert_query( certobj, "serial" ), "\\n" );
		debug_print( "issuer ..........: ", cert_query( certobj, "issuer" ), "\\n" );
		debug_print( "subject .........: ", cert_query( certobj, "subject" ), "\\n" );
		for(idx = 1;( tmp = cert_query( certobj, "subject", idx ) );idx++){
			debug_print( "altSubjectName[", idx, "]: ", tmp, "\\n" );
		}
		debug_print( "notBefore .......: ", cert_query( certobj, "not-before" ), "\\n" );
		debug_print( "notAfter ........: ", cert_query( certobj, "not-after" ), "\\n" );
		debug_print( "fpr (SHA-1) .....: ", cert_query( certobj, "fpr-sha-1" ), "\\n" );
		debug_print( "fpr (SHA-256) ...: ", cert_query( certobj, "fpr-sha-256" ), "\\n" );
		debug_print( "hostnames .......: ", cert_query( certobj, "hostnames" ), "\\n" );
	}
	fpr = cert_query( certobj, "fpr-sha-256" );
	if(!fpr){
		cert_close( certobj );
		set_kb_item( name: "HostDetails/SSLInfo/" + port, value: "[ERROR]" );
		log_message( data: "The certificates SHA-256 fingerprint of the remote service cannot be gathered!", port: port );
		return;
	}
	prefix = "HostDetails/Cert/" + fpr;
	if(isnull( get_kb_item( prefix + "/type" ) )){
		set_kb_item( name: prefix + "/type", value: "X.509" );
		set_kb_item( name: prefix + "/serial", value: cert_query( certobj, "serial" ) );
		set_kb_item( name: prefix + "/issuer", value: cert_query( certobj, "issuer" ) );
		set_kb_item( name: prefix + "/subject", value: cert_query( certobj, "subject" ) );
		for(idx = 1;( tmp = cert_query( certobj, "subject",  idx ) );idx++){
			set_kb_item( name: prefix + "/subject/" + idx, value: tmp );
		}
		set_kb_item( name: prefix + "/notBefore", value: cert_query( certobj, "not-before" ) );
		set_kb_item( name: prefix + "/notAfter", value: cert_query( certobj, "not-after" ) );
		set_kb_item( name: prefix + "/fprSHA1", value: cert_query( certobj, "fpr-sha-1" ) );
		set_kb_item( name: prefix + "/fprSHA256", value: cert_query( certobj, "fpr-sha-256" ) );
		set_kb_item( name: prefix + "/image", value: base64( str: cert_query( certobj, "image" ) ) );
		set_kb_item( name: prefix + "/algorithm", value: cert_query( certobj, "algorithm-name" ) );
		hostnames = cert_query( certobj, "hostnames" );
		if(!isnull( hostnames )){
			tmp = "";
			for item in hostnames {
				if(tmp != ""){
					tmp += ",";
				}
				tmp += item;
			}
			set_kb_item( name: prefix + "/hostnames", value: tmp );
		}
	}
	cert_close( certobj );
	set_kb_item( name: "HostDetails/SSLInfo/" + port, value: fpr );
	set_kb_item( name: "ssl/cert/avail", value: TRUE );
}
func report_ssl_cert_details(  ){
	var oid, certs, key, tmp, fpr, issuer, serial, not_before, not_after, image;
	var ssls, collected_certs, port, host, report;
	oid = "1.3.6.1.4.1.25623.1.0.103692";
	certs = get_kb_list( "HostDetails/Cert/*/type" );
	if(certs){
		for key in keys( certs ) {
			tmp = split( buffer: key, sep: "/", keep: FALSE );
			fpr = tmp[2];
			issuer = get_kb_item( "HostDetails/Cert/" + fpr + "/issuer" );
			serial = get_kb_item( "HostDetails/Cert/" + fpr + "/serial" );
			not_before = get_kb_item( "HostDetails/Cert/" + fpr + "/notBefore" );
			not_after = get_kb_item( "HostDetails/Cert/" + fpr + "/notAfter" );
			image = get_kb_item( "HostDetails/Cert/" + fpr + "/image" );
			tmp = "issuer:" + issuer + "|serial:" + serial + "|notBefore:" + not_before + "|notAfter:" + not_after;
			report_host_detail_single( name: "Cert:" + fpr, value: "x509:" + image, nvt: oid, desc: "SSL/TLS Certificate" );
			report_host_detail_single( name: "SSLDetails:" + fpr, value: tmp, nvt: oid, desc: "SSL/TLS Certificate Details" );
		}
	}
	ssls = get_kb_list( "HostDetails/SSLInfo/*" );
	if(ssls){
		collected_certs = make_list();
		for key in keys( ssls ) {
			tmp = split( buffer: key, sep: "/", keep: FALSE );
			port = tmp[2];
			host = tmp[3];
			tmp = port + ":" + host + ":" + get_kb_item( key );
			report_host_detail_single( name: "SSLInfo", value: tmp, nvt: oid, desc: "SSL/TLS Certificate Information" );
			key = "HostDetails/Cert/" + fpr + "/";
			collected_certs[port] = key;
		}
		for port in keys( collected_certs ) {
			report = "The following certificate details of the remote service were collected.\n";
			report += cert_summary( key: collected_certs[port] );
			log_message( data: report, port: port );
		}
	}
}
portlist = get_kb_list( "ssl_tls/port" );
for port in portlist {
	cert = get_server_cert( port: port );
	if(cert){
		read_and_parse_certs( cert: cert, port: port );
	}
}
report_ssl_cert_details();
exit( 0 );

