if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69419" );
	script_cve_id( "CVE-2011-0414" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_name( "Debian Security Advisory DSA 2208-2 (bind9)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202208-2" );
	script_tag( name: "insight", value: "The BIND, a DNS server, contains a defect related to the processing of
new DNSSEC DS records by the caching resolver, which may lead to name
resolution failures in the delegated zone.  If DNSSEC validation is
enabled, this issue can make domains ending in .COM unavailable when
the DS record for .COM is added to the DNS root zone on March 31st,
2011.  An unpatched server which is affected by this issue can be
restarted, thus re-enabling resolution of .COM domains.

Configurations not using DNSSEC validations are not affected by this
usse.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:9.6.ESV.R4+dfsg-0+lenny1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to bind9
announced via advisory DSA 2208-2." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-50", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns58", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc50", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc50", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg50", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres50", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.6.ESV.R4+dfsg-0+lenny1", rls: "DEB5" ) ) != NULL){
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

