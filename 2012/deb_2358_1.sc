if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70571" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:33:46 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2358-1 (openjdk-6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202358-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Java platform.  This combines the two previous
openjdk-6 advisories, DSA-2311-1 and DSA-2356-1.

CVE-2011-0862
Integer overflow errors in the JPEG and font parser allow
untrusted code (including applets) to elevate its privileges.

CVE-2011-0864
Hotspot, the just-in-time compiler in OpenJDK, mishandled
certain byte code instructions, allowing untrusted code
(including applets) to crash the virtual machine.

CVE-2011-0865
A race condition in signed object deserialization could
allow untrusted code to modify signed content, apparently
leaving its signature intact.

CVE-2011-0867
Untrusted code (including applets) could access information
about network interfaces which was not intended to be public.
(Note that the interface MAC address is still available to
untrusted code.)

Description truncated. Please see the referenced advisory for more information.

For the oldstable distribution (lenny), these problems have been fixed
in version 6b18-1.8.10-0~lenny1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openjdk-6 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openjdk-6
announced via advisory DSA 2358-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openjdk-6-dbg", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-demo", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-doc", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jdk", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-headless", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-jre-lib", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openjdk-6-source", ver: "6b18-1.8.10-0~lenny2", rls: "DEB5" ) ) != NULL){
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

