if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891464" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-10915" );
	script_name( "Debian LTS: Security Advisory for postgresql-9.4 (DLA-1464-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-15 00:00:00 +0200 (Wed, 15 Aug 2018)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "postgresql-9.4 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
9.4.19-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages." );
	script_tag( name: "summary", value: "An unprivileged user of dblink or postgres_fdw could bypass the checks
intended to prevent use of server-side credentials, such as a ~/.pgpass
file owned by the operating-system user running the server. Servers
allowing peer authentication on local connections are particularly
vulnerable. Other attacks such as SQL injection into a postgres_fdw
session are also possible. Attacking postgres_fdw in this way requires
the ability to create a foreign server object with selected connection
parameters, but any user with access to dblink could exploit the
problem. In general, an attacker with the ability to select the
connection parameters for a libpq-using application could cause
mischief, though other plausible attack scenarios are harder to think
of. Our thanks to Andrew Krasichkov for reporting this issue." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libecpg6", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpq5", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-9.4-dbg", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-client-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-contrib-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-doc-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plperl-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-plpython3-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-pltcl-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-server-dev-9.4", ver: "9.4.19-0+deb8u1", rls: "DEB8" ) )){
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

