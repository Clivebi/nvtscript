if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704652" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-11501" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 15:10:00 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-04-05 03:00:11 +0000 (Sun, 05 Apr 2020)" );
	script_name( "Debian: Security Advisory for gnutls28 (DSA-4652-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4652.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4652-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls28'
  package(s) announced via the DSA-4652-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was reported in the DTLS protocol implementation in GnuTLS, a
library implementing the TLS and SSL protocols. The DTLS client would
not contribute any randomness to the DTLS negotiation, breaking the
security guarantees of the DTLS protocol." );
	script_tag( name: "affected", value: "'gnutls28' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 3.6.7-4+deb10u3.

We recommend that you upgrade your gnutls28 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gnutls-bin", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnutls-doc", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls-dane0", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls-openssl27", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls28-dev", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutls30", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgnutlsxx28", ver: "3.6.7-4+deb10u3", rls: "DEB10" ) )){
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

