require("secpod_ssl_ciphers.inc.sc");
cipher_arrays = make_list( keys( sslv3_tls_ciphers ) );
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900238" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SSL/TLS: Cipher Settings" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "SSL and TLS" );
	for c in keys( cipher_arrays ) {
		v = FALSE;
		n = split( buffer: cipher_arrays[c], sep: " : ", keep: FALSE );
		if(isnull( n[0] ) || isnull( n[1] )){
			continue;
		}
		if( ContainsString( n[1], "Weak cipher" ) ) {
			v = "Weak cipher;Null cipher;Medium cipher;Strong cipher";
		}
		else {
			if( ContainsString( n[1], "Null cipher" ) ) {
				v = "Null cipher;Weak cipher;Medium cipher;Strong cipher";
			}
			else {
				if( ContainsString( n[1], "Medium cipher" ) ) {
					v = "Medium cipher;Null cipher;Weak cipher;Strong cipher";
				}
				else {
					if( ContainsString( n[1], "Strong cipher" ) ) {
						v = "Strong cipher;Null cipher;Weak cipher;Medium cipher";
					}
					else {
						continue;
					}
				}
			}
		}
		if(v){
			script_add_preference( name: n[0], type: "radio", value: v );
		}
	}
	script_tag( name: "summary", value: "This plugin allows to overwrite the internal classification
  of SSL/TLS Ciphers used for the reporting of Strong, Medium and Weak Ciphers within the
  following VTs:

  - SSL/TLS: Report Non Weak Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.103441)

  - SSL/TLS: Report Medium Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.902816)

  - SSL/TLS: Report Weak Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.103440)

  - SSL/TLS: Report 'Null' Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.108022)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
for c in keys( cipher_arrays ) {
	n = split( buffer: cipher_arrays[c], sep: " : ", keep: FALSE );
	if(isnull( n[0] ) || isnull( n[1] )){
		continue;
	}
	v = script_get_preference( n[0] );
	if(!v){
		continue;
	}
	if(!ContainsString( n[1], v )){
		set_kb_item( name: "ssl/ciphers/override/" + n[0] + " : " + n[1], value: v );
	}
}
exit( 0 );

