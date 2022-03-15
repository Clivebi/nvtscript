if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103140" );
	script_version( "2021-10-01T07:04:12+0000" );
	script_tag( name: "last_modification", value: "2021-10-01 07:04:12 +0000 (Fri, 01 Oct 2021)" );
	script_tag( name: "creation_date", value: "2011-04-27 15:13:59 +0200 (Wed, 27 Apr 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSL/TLS: Certificate - Self-Signed Certificate Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "ssl_cert_details.sc" );
	script_mandatory_keys( "ssl/cert/avail" );
	script_xref( name: "URL", value: "http://en.wikipedia.org/wiki/Self-signed_certificate" );
	script_tag( name: "summary", value: "The SSL/TLS certificate on this port is self-signed." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
require("global_settings.inc.sc");
require("list_array_func.inc.sc");
problematic_keys = make_array();
ssls = get_kb_list( "HostDetails/SSLInfo/*" );
if(!isnull( ssls )){
	for key in keys( ssls ) {
		tmp = split( buffer: key, sep: "/", keep: FALSE );
		port = tmp[2];
		vhost = tmp[3];
		fprlist = get_kb_item( key );
		if(!fprlist){
			continue;
		}
		tmpfpr = split( buffer: fprlist, sep: ",", keep: FALSE );
		fpr = tmpfpr[0];
		if(fpr[0] == "["){
			#debug_print( "A SSL/TLS certificate on port ", port, " (" + vhost + ")", " is erroneous.", level: 0 );
			continue;
		}
		key = "HostDetails/Cert/" + fpr + "/";
		issuer = get_kb_item( key + "issuer" );
		subject = get_kb_item( key + "subject" );
		if(issuer == subject){
			problematic_keys[port] = key;
		}
	}
	for port in keys( problematic_keys ) {
		report = "The certificate of the remote service is self signed.\n";
		report += cert_summary( key: problematic_keys[port] );
		log_message( data: report, port: port );
	}
	exit( 0 );
}
exit( 99 );

