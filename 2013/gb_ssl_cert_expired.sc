if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103955" );
	script_version( "$Revision: 11103 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-24 12:37:26 +0200 (Fri, 24 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2013-11-25 12:37:04 +0700 (Mon, 25 Nov 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "SSL/TLS: Certificate Expired" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "ssl_cert_details.sc" );
	script_mandatory_keys( "ssl/cert/avail" );
	script_tag( name: "insight", value: "This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have already expired." );
	script_tag( name: "solution", value: "Replace the SSL/TLS certificate by a new one." );
	script_tag( name: "summary", value: "The remote server's SSL/TLS certificate has already expired." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("ssl_funcs.inc.sc");
require("byte_func.inc.sc");
ssls = get_kb_list( "HostDetails/SSLInfo/*" );
if(!isnull( ssls )){
	now = isotime_now();
	if(strlen( now ) <= 0){
		exit( 0 );
	}
	expired_keys = make_array();
	for key in keys( ssls ) {
		tmp = split( buffer: key, sep: "/", keep: FALSE );
		port = tmp[2];
		vhost = tmp[3];
		fprlist = get_kb_item( key );
		if(!fprlist){
			continue;
		}
		result = check_cert_validity( fprlist: fprlist, port: port, vhost: vhost, check_for: "expired", now: now, timeframe: 0 );
		if(result){
			expired_keys[port] = result;
		}
	}
	for port in keys( expired_keys ) {
		report = "The certificate of the remote service expired on ";
		report += isotime_print( get_kb_item( expired_keys[port] + "notAfter" ) ) + ".\n";
		report += cert_summary( key: expired_keys[port] );
		security_message( data: report, port: port );
	}
	exit( 0 );
}
exit( 99 );

