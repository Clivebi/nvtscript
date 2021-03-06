if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702854" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0044", "CVE-2014-0045" );
	script_name( "Debian Security Advisory DSA 2854-1 (mumble - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-05 00:00:00 +0100 (Wed, 05 Feb 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2854.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mumble on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.2.3-349-g315b5f5-2.2+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your mumble packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in mumble, a low latency VoIP
client. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2014-0044
It was discovered that a malformed Opus voice packet sent to a
Mumble client could trigger a NULL pointer dereference or an
out-of-bounds array access. A malicious remote attacker could
exploit this flaw to mount a denial of service attack against a
mumble client by causing the application to crash.

CVE-2014-0045
It was discovered that a malformed Opus voice packet sent to a
Mumble client could trigger a heap-based buffer overflow. A
malicious remote attacker could use this flaw to cause a client
crash (denial of service) or potentially use it to execute
arbitrary code.

The oldstable distribution (squeeze) is not affected by these problems." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mumble", ver: "1.2.3-349-g315b5f5-2.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mumble-dbg", ver: "1.2.3-349-g315b5f5-2.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mumble-server", ver: "1.2.3-349-g315b5f5-2.2+deb7u1", rls: "DEB7" ) ) != NULL){
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

