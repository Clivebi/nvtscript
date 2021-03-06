default_domain = "example.com";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80086" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 12990 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-09 11:42:04 +0100 (Wed, 09 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SMTP settings" );
	script_category( ACT_SETTINGS );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi and Renaud Deraison" );
	script_family( "Settings" );
	script_add_preference( name: "Third party domain :", type: "entry", value: default_domain );
	script_add_preference( name: "From address : ", type: "entry", value: "nobody@example.com" );
	script_add_preference( name: "To address : ", type: "entry", value: "postmaster@[AUTO_REPLACED_IP]" );
	script_tag( name: "summary", value: "This script just sets a couple of SMTP parameters.

  Several checks need to use a third party host/domain name to work properly.

  The checks that rely on this are SMTP or DNS relay checks.

  By default, example.com is being used. However, under some circumstances,
  this may make leak packets from your network to this domain, thus
  compromising the privacy of your tests. You may want to change this
  value to maximize your privacy.

  Note that you absolutely need this option to be set to a
  *third party* domain. This means a domain that has *nothing
  to do* with the domain name of the network you are testing." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
fromaddr = script_get_preference( "From address : " );
toaddr = script_get_preference( "To address : " );
if(!fromaddr){
	fromaddr = "nobody@example.com";
}
if(!toaddr){
	toaddr = "postmaster@[AUTO_REPLACED_IP]";
}
if(ContainsString( toaddr, "AUTO_REPLACED_IP" )){
	dstip = get_host_ip();
	toaddr = ereg_replace( pattern: "AUTO_REPLACED_IP", string: toaddr, replace: dstip );
}
if(ContainsString( toaddr, "AUTO_REPLACED_ADDR" )){
	dstaddr = get_host_name();
	toaddr = ereg_replace( pattern: "AUTO_REPLACED_ADDR", string: toaddr, replace: dstaddr );
}
set_kb_item( name: "SMTP/headers/From", value: fromaddr );
set_kb_item( name: "SMTP/headers/To", value: toaddr );
domain = script_get_preference( "Third party domain :" );
if(!domain){
	domain = default_domain;
}
set_kb_item( name: "Settings/third_party_domain", value: domain );
exit( 0 );

