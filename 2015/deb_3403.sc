if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703403" );
	script_version( "$Revision: 14278 $" );
	script_name( "Debian Security Advisory DSA 3403-1 (libcommons-collections3-java - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-24 00:00:00 +0100 (Tue, 24 Nov 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3403.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "libcommons-collections3-java on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 3.2.1-5+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 3.2.1-7+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 3.2.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.2-1.

We recommend that you upgrade your libcommons-collections3-java packages." );
	script_tag( name: "summary", value: "This update backports changes from the
commons-collections 3.2.2 release which disable the deserialisation of the functors
classes unless the system property
org.apache.commons.collections.enableUnsafeSerialization is set to true
. This fixes a vulnerability in unsafe applications
deserialising objects from untrusted sources without sanitising the
input data. Classes considered unsafe are: CloneTransformer, ForClosure,
InstantiateFactory, InstantiateTransformer, InvokerTransformer,
PrototypeCloneFactory, PrototypeSerializationFactory and WhileClosure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcommons-collections3-java", ver: "3.2.1-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-collections3-java-doc", ver: "3.2.1-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-collections3-java", ver: "3.2.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-collections3-java-doc", ver: "3.2.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-collections3-java", ver: "3.2.1-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-collections3-java-doc", ver: "3.2.1-7+deb8u1", rls: "DEB8" ) ) != NULL){
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

