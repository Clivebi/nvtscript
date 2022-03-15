if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704661" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-1967" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-22 03:00:04 +0000 (Wed, 22 Apr 2020)" );
	script_name( "Debian: Security Advisory for openssl (DSA-4661-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4661.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4661-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the DSA-4661-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Bernd Edlinger discovered that malformed data passed to the
SSL_check_chain() function during or after a TLS 1.3 handshake could
cause a NULL dereference, resulting in denial of service.

The oldstable distribution (stretch) is not affected." );
	script_tag( name: "affected", value: "'openssl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.1.1d-0+deb10u3.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.1.1d-0+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.1.1d-0+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.1d-0+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.1.1d-0+deb10u3", rls: "DEB10" ) )){
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

