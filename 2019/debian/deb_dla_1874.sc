if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891874" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2007-2138", "CVE-2019-10208" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-10 02:00:07 +0000 (Sat, 10 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for postgresql-9.4 (DLA-1874-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1874-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-9.4'
  package(s) announced via the DLA-1874-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "* CVE-2019-10208: `TYPE` in `pg_temp` executes arbitrary SQL during
`SECURITY DEFINER` execution

Versions Affected: 9.4 - 11

Given a suitable `SECURITY DEFINER` function, an attacker can execute
arbitrary SQL under the identity of the function owner. An attack
requires `EXECUTE` permission on the function, which must itself contain
a function call having inexact argument type match. For example,
`length('foo'::varchar)` and `length('foo')` are inexact, while
`length('foo'::text)` is exact. As part of exploiting this
vulnerability, the attacker uses `CREATE DOMAIN` to create a type in a
`pg_temp` schema. The attack pattern and fix are similar to that for
CVE-2007-2138.

Writing `SECURITY DEFINER` functions continues to require following the
considerations noted in the documentation:

The PostgreSQL project thanks Tom Lane for reporting this problem." );
	script_tag( name: "affected", value: "'postgresql-9.4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
9.4.24-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg6", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq5", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.4-dbg", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-client-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-contrib-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-doc-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plperl-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython3-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-pltcl-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-server-dev-9.4", ver: "9.4.24-0+deb8u1", rls: "DEB8" ) )){
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

