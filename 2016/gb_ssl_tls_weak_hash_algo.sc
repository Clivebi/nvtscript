if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105880" );
	script_version( "2021-09-24T07:45:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:45:50 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-22 17:35:50 +0200 (Mon, 22 Aug 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_name( "SSL/TLS: Certificate Signed Using A Weak Signature Algorithm" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssl_tls_cert_chain_get.sc" );
	script_mandatory_keys( "ssl_tls/port", "ssl_tls/cert_chain/extracted" );
	script_add_preference( name: "SHA-1 fingerprints of CA certificates to trust", type: "entry", value: "", id: 1 );
	script_xref( name: "URL", value: "https://blog.mozilla.org/security/2014/09/23/phasing-out-certificates-with-sha-1-based-signature-algorithms/" );
	script_tag( name: "insight", value: "The following hashing algorithms used for signing SSL/TLS certificates are considered cryptographically weak
  and not secure enough for ongoing use:

  - Secure Hash Algorithm 1 (SHA-1)

  - Message Digest 5 (MD5)

  - Message Digest 4 (MD4)

  - Message Digest 2 (MD2)

  Beginning as late as January 2017 and as early as June 2016, browser developers such as Microsoft and Google will begin warning users when visiting
  web sites that use SHA-1 signed Secure Socket Layer (SSL) certificates.

  NOTE: The script preference allows to set one or more custom SHA-1 fingerprints of CA certificates which are trusted by this routine. The fingerprints
  needs to be passed comma-separated and case-insensitive:

  Fingerprint1

  or

  fingerprint1,Fingerprint2" );
	script_tag( name: "solution", value: "Servers that use SSL/TLS certificates signed with a weak SHA-1, MD5, MD4 or MD2 hashing algorithm will need to obtain new
  SHA-2 signed SSL/TLS certificates to avoid web browser SSL/TLS certificate warnings." );
	script_tag( name: "vuldetect", value: "Check which hashing algorithm was used to sign the remote SSL/TLS certificate." );
	script_tag( name: "summary", value: "The remote service is using a SSL/TLS certificate in the certificate chain that has been signed using a
  cryptographically weak hashing algorithm." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("ssl_funcs.inc.sc");
require("CAs.inc.sc");
require("byte_func.inc.sc");
require("http_func.inc.sc");
bad_algos = make_list( "md2WithRSAEncryption",
	 "md4WithRSAEncryption",
	 "md5WithRSAEncryption",
	 "sha1WithRSAEncryption" );
trusted_fps = script_get_preference( name: "SHA-1 fingerprints of CA certificates to trust", id: 1 );
func is_custom_trusted_fp( fingerprint, port ){
	var fingerprint, port, fp_list, fp, test_list, invalid_list, invalid, invalid_report;
	if(!trusted_fps){
		return;
	}
	fp_list = split( buffer: trusted_fps, sep: ",", keep: FALSE );
	if(max_index( fp_list ) == 0){
		return;
	}
	valid_list = make_list();
	invalid_list = make_list();
	for fp in fp_list {
		if( ereg( pattern: "^[a-fA-F0-9]{40}$", string: fp ) ){
			valid_list = make_list( valid_list,
				 fp );
		}
		else {
			invalid_list = make_list( invalid_list,
				 fp );
		}
	}
	for invalid in invalid_list {
		invalid_report += invalid + "\n";
	}
	if(invalid_report){
		invalid_report = "The following custom but invalid SHA-1 fingerprints were passed via the script preference: \n\n" + invalid_report;
		invalid_report += "\nThis fingerprints will be ignored by this routine. Please attach a correct (comma-separated) list of SHA-1 fingerprints.";
		log_message( port: port, data: invalid_report );
	}
	for valid in valid_list {
		if(tolower( valid ) == tolower( fingerprint )){
			return TRUE;
		}
	}
	return;
}
func check_algos( port ){
	var port, c, algos, f, certobj, fpr_sha_1, subject, algorithm_name, algos;
	if(!c = get_kb_list( "ssl_tls/cert_chain/" + port + "/certs/*" )){
		exit( 0 );
	}
	algos = make_list();
	for f in c {
		f = base64_decode( str: f );
		if(!certobj = cert_open( f )){
			continue;
		}
		fpr_sha_1 = cert_query( certobj, "fpr-sha-1" );
		if(fpr_sha_1 && ( is_known_rootCA( fingerprint: fpr_sha_1 ) || is_custom_trusted_fp( fingerprint: fpr_sha_1, port: port ) )){
			cert_close( certobj );
			continue;
		}
		subject = cert_query( certobj, "subject" );
		if(algorithm_name = cert_query( certobj, "algorithm-name" )){
			algos = make_list( algos,
				 subject + ">##<" + algorithm_name );
		}
		cert_close( certobj );
	}
	if(algos){
		return nasl_make_list_unique( algos );
	}
	return;
}
if(!port = tls_ssl_get_port()){
	exit( 0 );
}
if(ret = check_algos( port: port )){
	vuln = FALSE;
	for a in ret {
		sa = split( buffer: a, sep: ">##<", keep: FALSE );
		algo = sa[1];
		subj = sa[0];
		if(in_array( search: algo, array: bad_algos )){
			vuln = TRUE;
			report_algos += "Subject:              " + subj + "\nSignature Algorithm:  " + algo + "\n\n";
		}
	}
	if(vuln){
		report = "The following certificates are part of the certificate chain but using insecure signature algorithms:\n\n" + report_algos;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

