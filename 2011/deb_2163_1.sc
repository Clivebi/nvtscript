if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68996" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0696", "CVE-2011-0697" );
	script_name( "Debian Security Advisory DSA 2163-1 (python-django)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202163-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the django web development
framework:

CVE-2011-0696

For several reasons the internal CSRF protection was not used to
validate ajax requests in the past. However, it was discovered that
this exception can be exploited with a combination of browser plugins
and redirects and thus is not sufficient.

CVE-2011-0697

It was discovered that the file upload form is prone to cross-site
scripting attacks via the file name.

It is important to note that this update introduces minor backward
incompatibilities due to the fixes for the above issues.

Packages in the oldstable distribution (lenny) are not affected by these
problems.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.3-3+squeeze1.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.2.5-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to python-django
announced via advisory DSA 2163-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-django", ver: "1.2.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.2.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
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

