if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69988" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-2688" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2279-1 (libapache2-mod-authnz-external)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202279-1" );
	script_tag( name: "insight", value: "It was discovered that libapache2-mod-authnz-external, an apache
authentication module, is prone to an SQL injection via the $user
parameter.


For the stable distribution (squeeze), this problem has been fixed in
version 3.2.4-2+squeeze1.

The oldstable distribution (lenny) does not contain
libapache2-mod-authnz-external

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.4-2.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libapache2-mod-authnz-external packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libapache2-mod-authnz-external
announced via advisory DSA 2279-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-mod-authnz-external", ver: "3.2.4-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

