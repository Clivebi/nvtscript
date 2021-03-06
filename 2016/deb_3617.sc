if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703617" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-3219", "CVE-2016-4428" );
	script_name( "Debian Security Advisory DSA 3617-1 (horizon - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-06 00:00:00 +0200 (Wed, 06 Jul 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3617.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "horizon on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2014.1.3-7+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 3:9.0.1-2.

For the unstable distribution (sid), these problems have been fixed in
version 3:9.0.1-2.

We recommend that you upgrade your horizon packages." );
	script_tag( name: "summary", value: "Two cross-site scripting vulnerabilities
have been found in Horizon, a web application to control an OpenStack cloud." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "horizon-doc", ver: "3:9.0.1-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openstack-dashboard", ver: "3:9.0.1-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openstack-dashboard-apache", ver: "3:9.0.1-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-horizon", ver: "3:9.0.1-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openstack-dashboard", ver: "2014.1.3-7+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openstack-dashboard-apache", ver: "2014.1.3-7+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-django-horizon", ver: "2014.1.3-7+deb8u2", rls: "DEB8" ) ) != NULL){
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

