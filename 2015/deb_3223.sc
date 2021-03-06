if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703223" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1798", "CVE-2015-1799" );
	script_name( "Debian Security Advisory DSA 3223-1 (ntp - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-12 00:00:00 +0200 (Sun, 12 Apr 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3223.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ntp on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u4.

For the unstable distribution (sid), these problems have been fixed in
version 1:4.2.6.p5+dfsg-7.

We recommend that you upgrade your ntp packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were
discovered in ntp, an implementation of the Network Time Protocol:

CVE-2015-1798
When configured to use a symmetric key with an NTP peer, ntpd would
accept packets without MAC as if they had a valid MAC. This could
allow a remote attacker to bypass the packet authentication and send
malicious packets without having to know the symmetric key.

CVE-2015-1799
When peering with other NTP hosts using authenticated symmetric
association, ntpd would update its internal state variables before
the MAC of the NTP messages was validated. This could allow a remote
attacker to cause a denial of service by impeding synchronization
between NTP peers.

Additionally, it was discovered that generating MD5 keys using ntp-keygen
on big endian machines would either trigger an endless loop, or generate
non-random keys." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp-doc", ver: "1:4.2.6.p5+dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntpdate", ver: "1:4.2.6.p5+dfsg-2+deb7u4", rls: "DEB7" ) ) != NULL){
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

