if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703154" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-9297", "CVE-2014-9298" );
	script_name( "Debian Security Advisory DSA 3154-1 (ntp - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-05 00:00:00 +0100 (Thu, 05 Feb 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3154.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ntp on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u2.

For the unstable distribution (sid), these problems have been fixed in
version 1:4.2.6.p5+dfsg-4.

We recommend that you upgrade your ntp packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were
discovered in the ntp package, an implementation of the Network Time Protocol.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2014-9297
Stephen Roettger of the Google Security Team, Sebastian Krahmer of
the SUSE Security Team and Harlan Stenn of Network Time Foundation
discovered that the length value in extension fields is not properly
validated in several code paths in ntp_crypto.c, which could lead to
information leakage or denial of service (ntpd crash).

CVE-2014-9298
Stephen Roettger of the Google Security Team reported that ACLs
based on IPv6 ::1 addresses can be bypassed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp-doc", ver: "1:4.2.6.p5+dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntpdate", ver: "1:4.2.6.p5+dfsg-2+deb7u2", rls: "DEB7" ) ) != NULL){
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

