if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702895" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-2744", "CVE-2014-2745" );
	script_name( "Debian Security Advisory DSA 2895-1 (prosody - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-06 00:00:00 +0200 (Sun, 06 Apr 2014)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2895.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "prosody on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 0.8.2-4+deb7u1 of prosody.

For the unstable distribution (sid), this problem has been fixed in
version 0.9.4-1 of prosody.

For the stable distribution (wheezy), this problem has been fixed in
version 1.2.0-5+deb7u1 of lua-expat.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.0-1 lua-expat.

We recommend that you upgrade your prosody and lua-expat packages." );
	script_tag( name: "summary", value: "A denial-of-service vulnerability
has been reported in Prosody, a XMPP server. If compression is enabled, an
attacker might send highly-compressed XML elements (attack known as zip bomb)
over XMPP streams and consume all the resources of the server.

The SAX XML parser lua-expat is also affected by this issues." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "prosody", ver: "0.8.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

