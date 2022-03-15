if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704439" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-10130" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 14:08:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-05-11 02:00:21 +0000 (Sat, 11 May 2019)" );
	script_name( "Debian Security Advisory DSA 4439-1 (postgresql-9.6 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4439.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4439-1" );
	script_xref( name: "URL", value: "https://www.postgresql.org/about/news/1939/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-9.6'
  package(s) announced via the DSA-4439-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Dean Rasheed discovered that row security policies in the PostgreSQL
database system could be bypassed.

For additional information please refer to the referenced upstream announcement." );
	script_tag( name: "affected", value: "'postgresql-9.6' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 9.6.13-0+deb9u1.

We recommend that you upgrade your postgresql-9.6 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq5", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.6-dbg", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-client-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-contrib-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-doc-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plperl-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython3-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-pltcl-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-server-dev-9.6", ver: "9.6.13-0+deb9u1", rls: "DEB9" ) )){
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

