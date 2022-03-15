if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892478" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-15 19:37:00 +0000 (Tue, 15 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-03 04:00:12 +0000 (Thu, 03 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for postgresql-9.6 (DLA-2478-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2478-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-9.6'
  package(s) announced via the DLA-2478-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been found in the PostgreSQL database system.

CVE-2020-25694

Peter Eisentraut found that database reconnections may drop options
from the original connection, such as encryption, which could lead
to information disclosure or a man-in-the-middle attack.

CVE-2020-25695

Etienne Stalmans reported that a user with permissions to create
non-temporary objects in an schema can execute arbitrary SQL
functions as a superuser.

CVE-2020-25696

Nick Cleaton found that the \\gset command modified variables that
control the psql behaviour, which could result in a compromised or
malicious server executing arbitrary code in the user session." );
	script_tag( name: "affected", value: "'postgresql-9.6' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
9.6.20-0+deb9u1.

We recommend that you upgrade your postgresql-9.6 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq5", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.6-dbg", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-client-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-contrib-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-doc-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plperl-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython3-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-pltcl-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-server-dev-9.6", ver: "9.6.20-0+deb9u1", rls: "DEB9" ) )){
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
exit( 0 );

