if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68998" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2010-4476", "CVE-2009-3555" );
	script_name( "Debian Security Advisory DSA 2161-2 (openjdk-6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202161-2" );
	script_tag( name: "insight", value: "It was discovered that the floating point parser in OpenJDK, an
implementation of the Java platform, can enter an infinite loop when
processing certain input strings.  Such input strings represent valid
numbers and can be contained in data supplied by an attacker over the
network, leading to a denial-of-service attack.

For the old stable distribution (lenny), this problem has been fixed
in version 6b18-1.8.3-2~lenny1.

Note that this update introduces an OpenJDK package based on the
IcedTea release 1.8.3 into the old stable distribution.  This
addresses several dozen security vulnerabilities, most of which are
only exploitable by malicious mobile code.  A notable exception is
CVE-2009-3555, the TLS renegotiation vulnerability.  This update
implements the protocol extension described in RFC 5746, addressing
this issue.

This update also includes a new version of Hotspot, the Java virtual
machine, which increases the default heap size on machines with
several GB of RAM.  If you run several JVMs on the same machine, you
might have to reduce the heap size by specifying a suitable -Xmx
argument in the invocation of the java command." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openjdk-6 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openjdk-6
announced via advisory DSA 2161-2." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b18-1.8.3-2~lenny1", rls: "DEB5" ) ) != NULL){
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

