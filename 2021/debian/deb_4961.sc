if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704961" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2021-38385" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-02 02:18:00 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-24 03:00:10 +0000 (Tue, 24 Aug 2021)" );
	script_name( "Debian: Security Advisory for tor (DSA-4961-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(11|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4961.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4961-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4961-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tor'
  package(s) announced via the DSA-4961-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Henry de Valence reported a flaw in the signature verification code in
Tor, a connection-based low-latency anonymous communication system. A
remote attacker can take advantage of this flaw to cause an assertion
failure, resulting in denial of service." );
	script_tag( name: "affected", value: "'tor' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (buster), this problem has been fixed
in version 0.3.5.16-1.

For the stable distribution (bullseye), this problem has been fixed in
version 0.4.5.10-1~deb11u1.

We recommend that you upgrade your tor packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tor", ver: "0.4.5.10-1~deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.4.5.10-1~deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor", ver: "0.3.5.16-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.3.5.16-1", rls: "DEB10" ) )){
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

