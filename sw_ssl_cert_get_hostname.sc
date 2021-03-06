if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111010" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-03-27 12:00:00 +0100 (Fri, 27 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: Hostname discovery from server certificate" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "SSL and TLS" );
	script_dependencies( "ssl_cert_details.sc", "toolcheck.sc" );
	script_mandatory_keys( "ssl/cert/avail" );
	script_tag( name: "summary", value: "It was possible to discover an additional hostname
  of this server from its certificate Common or Subject Alt Name." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("list_array_func.inc.sc");
require("host_details.inc.sc");
hostname = get_host_name();
hostip = get_host_ip();
resolvableFound = FALSE;
resolvableOtherFound = FALSE;
additionalFound = FALSE;
report = "";
resolvableHostnames = make_list();
resolvableOther = make_list();
additionalHostnames = make_list();
ipv4pattern = "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";
ipv6pattern = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
if(!defined_func( "resolve_host_name" )){
	if(!ping_cmd = get_kb_item( "Tools/Present/ping/bin" )){
		exit( 0 );
	}
	use_ping_cmd = TRUE;
	ping_args = make_list();
	i = 0;
	if( TARGET_IS_IPV6() ) {
		pattern = ipv6pattern;
	}
	else {
		pattern = ipv4pattern;
	}
	if(extra_cmd = get_kb_item( "Tools/Present/ping/extra_cmd" )){
		ping_args[i++] = extra_cmd;
	}
	ping_args[i++] = "-c 1";
	ping_args[i++] = "-W 1";
	ping_args[i++] = "-w 2";
}
tmpHostnames = get_kb_list( "HostDetails/Cert/*/hostnames" );
if(!isnull( tmpHostnames )){
	for certHostnames in keys( tmpHostnames ) {
		hostnames = get_kb_item( certHostnames );
		for tmpHostname in split( buffer: hostnames, sep: ",", keep: FALSE ) {
			if(!strlen( tmpHostname ) > 0 || ContainsString( tmpHostname, " " )){
				continue;
			}
			if(hostname == tmpHostname || ContainsString( tmpHostname, "*." ) || tmpHostname == "localhost" || tmpHostname == "localdomain"){
				continue;
			}
			if(eregmatch( pattern: ipv4pattern, string: tmpHostname ) || eregmatch( pattern: ipv6pattern, string: tmpHostname )){
				continue;
			}
			if( use_ping_cmd ){
				cnIp = pread( cmd: ping_cmd, argv: make_list( ping_cmd,
					 ping_args,
					 tmpHostname ), cd: TRUE );
				cnIpPing = eregmatch( pattern: pattern, string: cnIp );
				cnCheck = cnIpPing[0];
			}
			else {
				cnCheck = resolve_host_name( hostname: tmpHostname );
			}
			if( cnCheck ){
				if( hostip == cnCheck ){
					if(!in_array( search: tmpHostname, array: resolvableHostnames )){
						resolvableFound = TRUE;
						resolvableHostnames = make_list( resolvableHostnames,
							 tmpHostname );
					}
				}
				else {
					if(!in_array( search: tmpHostname, array: resolvableOther )){
						resolvableOtherFound = TRUE;
						resolvableOther = make_list( resolvableOther,
							 tmpHostname );
					}
				}
			}
			else {
				if(!in_array( search: tmpHostname, array: additionalHostnames )){
					additionalFound = TRUE;
					additionalHostnames = make_list( additionalHostnames,
						 tmpHostname );
				}
			}
		}
	}
}
if(resolvableFound){
	report += "The following additional and resolvable hostnames were detected:\n\n";
	resolvableHostnames = sort( resolvableHostnames );
	for tmp in resolvableHostnames {
		set_kb_item( name: "DNS_via_SSL_TLS_Cert", value: tmp );
		register_host_detail( name: "DNS-via-SSL-TLS-Cert", value: tmp, desc: "SSL/TLS: Hostname discovery from server certificate" );
		report += tmp + "\n";
		if(defined_func( "add_host_name" )){
			add_host_name( hostname: tmp, source: "SSL/TLS server certificate" );
		}
	}
	report += "\n";
}
if(resolvableOtherFound){
	report += "The following additional and resolvable hostnames pointing to a different host ip were detected:\n\n";
	resolvableOther = sort( resolvableOther );
	for tmp in resolvableOther {
		report += tmp + "\n";
	}
	report += "\n";
}
if(additionalFound){
	report += "The following additional but not resolvable hostnames were detected:\n\n";
	additionalHostnames = sort( additionalHostnames );
	for tmp in additionalHostnames {
		report += tmp + "\n";
	}
	report += "\n";
}
if(resolvableFound || additionalFound || resolvableOtherFound){
	log_message( port: 0, data: report );
}
exit( 0 );

