if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891753" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-04-09 02:00:10 +0000 (Tue, 09 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for proftpd-dfsg (DLA-1753-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1753-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/923926" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'proftpd-dfsg'
  package(s) announced via the DLA-1753-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several memory leaks were discovered in proftpd-dfsg, a versatile,
virtual-hosting FTP daemon, when mod_facl or mod_sftp
is used which could lead to memory exhaustion and a denial-of-service." );
	script_tag( name: "affected", value: "'proftpd-dfsg' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.3.5e-0+deb8u1.

We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-geoip", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.5e-0+deb8u1", rls: "DEB8" ) )){
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

