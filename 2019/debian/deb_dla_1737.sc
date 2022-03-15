if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891737" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-3871" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 05:29:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for pdns (DLA-1737-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00039.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1737-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924966" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pdns'
  package(s) announced via the DLA-1737-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in PowerDNS Authoritative Server before
4.0.7 and before 4.1.7. An insufficient validation of data coming from
the user when building a HTTP request from a DNS query in the HTTP
Connector of the Remote backend, allowing a remote user to cause a
denial of service by making the server connect to an invalid endpoint,
or possibly information disclosure by making the server connect to an
internal endpoint and somehow extracting meaningful information about
the response.

Only installations using the pdns-backend-remote package are affected." );
	script_tag( name: "affected", value: "'pdns' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.4.1-4+deb8u9.

We recommend that you upgrade your pdns packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-geo", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-ldap", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-lmdb", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-lua", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-mydns", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-mysql", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-pgsql", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-pipe", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-remote", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-sqlite3", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-server", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-server-dbg", ver: "3.4.1-4+deb8u9", rls: "DEB8" ) )){
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

