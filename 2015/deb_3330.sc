if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703330" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-3576", "CVE-2014-3600", "CVE-2014-3612" );
	script_name( "Debian Security Advisory DSA 3330-1 (activemq - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-07 00:00:00 +0200 (Fri, 07 Aug 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3330.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "activemq on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 5.6.0+dfsg-1+deb7u1. This update also fixes CVE-2014-3612 and CVE-2014-3600
.

For the stable distribution (jessie), this problem has been fixed in
version 5.6.0+dfsg1-4+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your activemq packages." );
	script_tag( name: "summary", value: "It was discovered that the Apache ActiveMQ message broker is susceptible
to denial of service through an undocumented, remote shutdown command." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "activemq", ver: "5.6.0+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivemq-java", ver: "5.6.0+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivemq-java-doc", ver: "5.6.0+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "activemq", ver: "5.6.0+dfsg1-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivemq-java", ver: "5.6.0+dfsg1-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivemq-java-doc", ver: "5.6.0+dfsg1-4+deb8u1", rls: "DEB8" ) ) != NULL){
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

