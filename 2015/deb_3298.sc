if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703298" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-1833" );
	script_name( "Debian Security Advisory DSA 3298-1 (jackrabbit - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-01 00:00:00 +0200 (Wed, 01 Jul 2015)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3298.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "jackrabbit on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 2.3.6-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.3.6-1+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 2.10.1-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.10.1-1.

We recommend that you upgrade your jackrabbit packages." );
	script_tag( name: "summary", value: "It was discovered that the Jackrabbit
WebDAV bundle was susceptible to a XXE/XEE attack. When processing a WebDAV
request body containing XML, the XML parser could be instructed to read content
from network resources accessible to the host, identified by URI schemes such as
http(s) or file. Depending on the WebDAV request, this could not only be used to
trigger internal network requests, but might also be used to insert said content
into the request, potentially exposing it to the attacker and others." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libjackrabbit-java", ver: "2.3.6-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

