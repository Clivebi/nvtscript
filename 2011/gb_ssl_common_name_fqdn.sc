if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103141" );
	script_version( "2020-08-24T15:47:14+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:47:14 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-27 15:13:59 +0200 (Wed, 27 Apr 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSL/TLS: Certificate - Subject Common Name Does Not Match Server FQDN" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "ssl_cert_details.sc" );
	script_mandatory_keys( "ssl/cert/avail" );
	script_tag( name: "summary", value: "The SSL/TLS certificate contains a common name (CN) that does not match the hostname." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("ssl_funcs.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("byte_func.inc.sc");
require("global_settings.inc.sc");
problematic_keys = make_array();
hostname = get_host_name();
ip = get_host_ip();
if(hostname == ip){
	exit( 0 );
}
if(hostname == "localhost" || ip == "127.0.0.1"){
	exit( 0 );
}
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
		hostnames = get_kb_item( key + "hostnames" );
		if(isnull( hostnames )){
			continue;
		}
		hostnamelist = split( buffer: hostnames, sep: ",", keep: FALSE );
		if(isnull( hostnamelist )){
			continue;
		}
		if(!in_array( search: hostname, array: hostnamelist )){
			notVuln = FALSE;
			for tmphostname in hostnamelist {
				comname = tmphostname;
				if(comname[0] == "*"){
					hn = stridx( hostname, "." );
					in = stridx( tmphostname, "." );
					if(( hn > 0 && in > 0 ) && substr( hostname, hn ) == substr( tmphostname, in )){
						notVuln = TRUE;
						continue;
					}
					hn = comname - "*.";
					if(hn == hostname){
						notVuln = TRUE;
						continue;
					}
				}
			}
			if(!notVuln){
				problematic_keys[port] = key;
			}
		}
	}
	for port in keys( problematic_keys ) {
		report = "The certificate of the remote service contains a common name (CN) that does not match the hostname \"" + hostname + "\".\n";
		report += cert_summary( key: problematic_keys[port] );
		log_message( data: report, port: port );
	}
	exit( 0 );
}
exit( 99 );

