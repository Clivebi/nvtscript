if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704115" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381" );
	script_name( "Debian Security Advisory DSA 4115-1 (quagga - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 00:00:00 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:41:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4115.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "quagga on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 0.99.23.1-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 1.1.1-3+deb9u2.

We recommend that you upgrade your quagga packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/quagga" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Quagga, a routing
daemon. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2018-5378
It was discovered that the Quagga BGP daemon, bgpd, does not
properly bounds check data sent with a NOTIFY to a peer, if an
attribute length is invalid. A configured BGP peer can take
advantage of this bug to read memory from the bgpd process or cause
a denial of service (daemon crash).

CVE-2018-5379
It was discovered that the Quagga BGP daemon, bgpd, can double-free
memory when processing certain forms of UPDATE message, containing
cluster-list and/or unknown attributes, resulting in a denial of
service (bgpd daemon crash).

CVE-2018-5380
It was discovered that the Quagga BGP daemon, bgpd, does not
properly handle internal BGP code-to-string conversion tables.


CVE-2018-5381
It was discovered that the Quagga BGP daemon, bgpd, can enter an
infinite loop if sent an invalid OPEN message by a configured peer.
A configured peer can take advantage of this flaw to cause a denial
of service (bgpd daemon not responding to any other events, BGP
sessions will drop and not be reestablished, unresponsive CLI
interface)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "quagga", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-bgpd", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-core", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-doc", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-isisd", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-ospf6d", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-ospfd", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-pimd", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-ripd", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-ripngd", ver: "1.1.1-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga", ver: "0.99.23.1-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-dbg", ver: "0.99.23.1-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quagga-doc", ver: "0.99.23.1-1+deb8u5", rls: "DEB8" ) )){
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

