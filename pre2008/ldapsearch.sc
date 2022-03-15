if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.91984" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-04-23 14:49:44 +0200 (Sun, 23 Apr 2006)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "LDAPsearch" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 Tarik El-Yassem/ITsec Security Services" );
	script_family( "General" );
	script_dependencies( "toolcheck.sc", "ldap_detect.sc", "ldap_null_base.sc", "ldap_null_bind.sc" );
	script_require_ports( "Services/ldap", 389, 636 );
	script_mandatory_keys( "ldap/detected", "Tools/Present/ldapsearch" );
	script_add_preference( name: "timelimit value (in seconds)", type: "entry", value: "3600" );
	script_add_preference( name: "sizelimit value", type: "entry", value: "500" );
	script_tag( name: "summary", value: "This plugins shows what information can be pulled of an LDAP server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ldap.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
func scanopts( port, type, value, host, timelimit, sizelimit ){
	var port, type, value, host, timelimit, sizelimit, i;
	i = 0;
	argv[i++] = "ldapsearch";
	argv[i++] = "-H";
	if( get_port_transport( port ) > ENCAPS_IP ){
		ldapuri = "ldaps://" + host + ":" + port;
	}
	else {
		ldapuri = "ldap://" + host + ":" + port;
	}
	argv[i++] = ldapuri;
	argv[i++] = "-x";
	argv[i++] = "-C";
	argv[i++] = "-b";
	argv[i++] = value;
	if(type != ""){
		argv[i++] = "-s";
		argv[i++] = "base";
	}
	if(type == "null-bind"){
		argv[i++] = "objectclass=*";
		argv[i++] = "-P3";
	}
	argv[i++] = "-l";
	argv[i++] = timelimit;
	argv[i++] = "-z";
	argv[i++] = sizelimit;
	return ( argv );
}
func getdc( res ){
	var res, r, n, i, patt, dc, value;
	r = split( buffer: res, sep: "," );
	n = 0;
	i = 0;
	patt = "dc=([a-zA-Z0-9-]+)";
	dc = eregmatch( string: r, pattern: patt, icase: TRUE );
	if(dc){
		value[i] = dc[n + 1];
		i++;
		n++;
		for line in r {
			if(dc[0]){
				r = ereg_replace( string: r, pattern: dc[0], replace: "XXXXX", icase: TRUE );
				dc = eregmatch( string: r, pattern: patt, icase: TRUE );
				value[i] = dc[n];
				i++;
				if(!dc[n]){
					exit( 0 );
				}
				n++;
			}
		}
	}
	if(!value){
		exit( 0 );
	}
	return ( value );
}
func makereport( res, args ){
	var res, args, s, x;
	if(!res){
		exit( 0 );
	}
	for x in args {
		s = s + x + " ";
	}
	result = "(Command was:\"" + s + "\")\n\n" + res + "\n";
	return result;
}
func res_check( res ){
	var res;
	if( IsMatchRegexp( res, "(S|s)uccess" ) && ContainsString( res, "LDAPv" ) ){
		return res;
	}
	else {
		return FALSE;
	}
}
timelimit = script_get_preference( "timelimit value (in seconds)" );
if(!timelimit){
	timelimit = 3600;
}
sizelimit = script_get_preference( "sizelimit value" );
if(!sizelimit){
	sizelimit = 500;
}
host = get_host_name();
port = ldap_get_port( default: 389 );
null_base = get_kb_item( "LDAP/" + port + "/NULL_BASE" );
null_bind = get_kb_item( "LDAP/" + port + "/NULL_BIND" );
ldapv3 = ldap_is_v3( port: port );
if( ldapv3 ){
	if(eregmatch( pattern: "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})", string: host ) || ContainsString( host, ":" )){
		exit( 0 );
	}
	host_dn = split( buffer: host, sep: ".", keep: FALSE );
	if(host_dn){
		first = 0;
		for tmp in host_dn {
			if( first == 0 ){
				first = 1;
				base_dn += "dc=" + tmp;
			}
			else {
				base_dn += ",dc=" + tmp;
			}
		}
		args = scanopts( port: port, type: "", value: base_dn, host: host, timelimit: timelimit, sizelimit: sizelimit );
		res = pread( cmd: "ldapsearch", argv: args, nice: 5 );
		tmpres = res_check( res: res );
		report = "Grabbed the following information:\n";
		if( tmpres ){
			report += makereport( res: res, args: args );
			log_message( port: port, data: report );
			exit( 0 );
		}
		else {
			if(ContainsString( res, "matchedDN:" )){
				base_dn = egrep( string: res, pattern: "^matchedDN: (.*)$", icase: TRUE );
				base_dn = ereg_replace( string: base_dn, pattern: "matchedDN: ", replace: "" );
				base_dn = chomp( base_dn );
				if(base_dn){
					args = scanopts( port: port, type: "", value: base_dn, host: host, timelimit: timelimit, sizelimit: sizelimit );
					res = pread( cmd: "ldapsearch", argv: args, nice: 5 );
					res = res_check( res: res );
					if(res){
						report += makereport( res: res, args: args );
						log_message( port: port, data: report );
						exit( 0 );
					}
				}
			}
		}
	}
}
else {
	if(null_base){
		type = "null-base";
		value = "";
		args = scanopts( port: port, type: type, value: value, host: host, timelimit: timelimit, sizelimit: sizelimit );
		res = pread( cmd: "ldapsearch", argv: args, nice: 5 );
		res = res_check( res: res );
		if(res){
			base_report = makereport( res: res, args: args );
		}
		if(null_bind && res){
			type = "null-bind";
			val = getdc( res: res );
			value = "dc=" + val[0] + ",dc=" + val[1];
			args = scanopts( port: port, type: type, value: value, host: host, timelimit: timelimit, sizelimit: sizelimit );
			res = pread( cmd: "ldapsearch", argv: args, nice: 5 );
			res = res_check( res: res );
			if(res){
				bind_report = makereport( res: res, args: args );
			}
		}
		if(bind_report || base_report){
			data = "Grabbed the following information with a null-bind, null-base request:\n";
			if( bind_report == base_report ){
				data += bind_report;
			}
			else {
				data += bind_report + base_report;
			}
			log_message( port: port, data: data );
		}
	}
}
exit( 0 );

