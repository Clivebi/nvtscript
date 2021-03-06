if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69417" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_cve_id( "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227" );
	script_name( "Debian Security Advisory DSA 2207-1 (tomcat5.5)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202207-1" );
	script_tag( name: "insight", value: "Various vulnerabilities have been discovered in the Tomcat Servlet and
JSP engine, resulting in denial of service, cross-site scripting,
information disclosure and WAR file traversal.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.5.26-5lenny2.

The stable distribution (squeeze) no longer contains tomcat5.5. tomcat6
is already fixed.

The unstable distribution (sid) no longer contains tomcat5.5. tomcat6
is already fixed." );
	script_tag( name: "solution", value: "We recommend that you upgrade your tomcat5.5 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to tomcat5.5
announced via advisory DSA 2207-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtomcat5.5-java", ver: "5.5.26-5lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat5.5", ver: "5.5.26-5lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat5.5-admin", ver: "5.5.26-5lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tomcat5.5-webapps", ver: "5.5.26-5lenny2", rls: "DEB5" ) ) != NULL){
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

