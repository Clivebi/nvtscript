if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891843" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-10162", "CVE-2019-10163" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-02 14:27:00 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-07-04 02:00:08 +0000 (Thu, 04 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for pdns (DLA-1843-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1843-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pdns'
  package(s) announced via the DLA-1843-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in pdns, an authoritative DNS
server which may result in denial of service via malformed zone records
and excessive NOTIFY packets in a master/slave setup.

CVE-2019-10162

An issue has been found in PowerDNS Authoritative Server allowing
an authorized user to cause the server to exit by inserting a
crafted record in a MASTER type zone under their control. The issue
is due to the fact that the Authoritative Server will exit when it
runs into a parsing error while looking up the NS/A/AAAA records it
is about to use for an outgoing notify.

CVE-2019-10163

An issue has been found in PowerDNS Authoritative Server allowing
a remote, authorized master server to cause a high CPU load or even
prevent any further updates to any slave zone by sending a large
number of NOTIFY messages. Note that only servers configured as
slaves are affected by this issue." );
	script_tag( name: "affected", value: "'pdns' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.1-4+deb8u10.

We recommend that you upgrade your pdns packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-geo", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-ldap", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-lmdb", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-lua", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-mydns", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-mysql", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-pgsql", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-pipe", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-remote", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-backend-sqlite3", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-server", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pdns-server-dbg", ver: "3.4.1-4+deb8u10", rls: "DEB8" ) )){
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

