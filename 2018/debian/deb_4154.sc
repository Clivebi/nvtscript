if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704154" );
	script_version( "2019-07-04T09:25:28+0000" );
	script_cve_id( "CVE-2015-5621", "CVE-2018-1000116" );
	script_name( "Debian Security Advisory DSA 4154-1 (net-snmp - security update)" );
	script_tag( name: "last_modification", value: "2019-07-04 09:25:28 +0000 (Thu, 04 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-03-28 00:00:00 +0200 (Wed, 28 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4154.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "net-snmp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 5.7.2.1+dfsg-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed
before the initial release.

We recommend that you upgrade your net-snmp packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/net-snmp" );
	script_tag( name: "summary", value: "A heap corruption vulnerability was discovered in net-snmp, a suite of
Simple Network Management Protocol applications, triggered when parsing
the PDU prior to the authentication process. A remote, unauthenticated
attacker can take advantage of this flaw to crash the snmpd process
(causing a denial of service) or, potentially, execute arbitrary code
with the privileges of the user running snmpd." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-base", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-dev", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp-perl", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp30", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsnmp30-dbg", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-netsnmp", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmp", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmpd", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "snmptrapd", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tkmib", ver: "5.7.2.1+dfsg-1+deb8u1", rls: "DEB8" ) )){
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

