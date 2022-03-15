if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704859" );
	script_version( "2021-02-23T04:00:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-23 04:00:08 +0000 (Tue, 23 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-23 04:00:08 +0000 (Tue, 23 Feb 2021)" );
	script_name( "Debian: Security Advisory for libzstd (DSA-4859-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4859.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4859-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4859-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libzstd'
  package(s) announced via the DSA-4859-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that zstd, a compression utility, was vulnerable to
a race condition: it temporarily exposed, during a very short
timeframe, a world-readable version of its input even if the original
file had restrictive permissions." );
	script_tag( name: "affected", value: "'libzstd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.3.8+dfsg-3+deb10u2.

We recommend that you upgrade your libzstd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzstd-dev", ver: "1.3.8+dfsg-3+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzstd1", ver: "1.3.8+dfsg-3+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zstd", ver: "1.3.8+dfsg-3+deb10u2", rls: "DEB10" ) )){
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
