if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71494" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2012-3817" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:14:19 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2517-1 (bind9)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202517-1" );
	script_tag( name: "insight", value: "Einar Lonn discovered that under certain conditions bind9, a DNS server,
may use cached data before initialization.  As a result, an attacker can
trigger and assertion failure on servers under high query load that do
DNSSEC validation.

For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze6.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1:9.8.1.dfsg.P1-4.2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your bind9 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to bind9
announced via advisory DSA 2517-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bind9", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-doc", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9-host", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bind9utils", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dnsutils", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "host", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind-dev", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbind9-60", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdns69", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisc62", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccc60", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libisccfg62", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblwres60", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lwresd", ver: "1:9.7.3.dfsg-1~squeeze6", rls: "DEB6" ) ) != NULL){
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

