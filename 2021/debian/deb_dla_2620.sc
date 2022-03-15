if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892620" );
	script_version( "2021-04-07T03:00:16+0000" );
	script_cve_id( "CVE-2021-23980" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-07 03:00:16 +0000 (Wed, 07 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-07 03:00:16 +0000 (Wed, 07 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for python-bleach (DLA-2620-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00006.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2620-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2620-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/986251" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-bleach'
  package(s) announced via the DLA-2620-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a cross-site scripting (XSS)
vulnerability in python-bleach, a whitelist-based HTML sanitisation
library." );
	script_tag( name: "affected", value: "'python-bleach' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
2.0-1+deb9u1.

We recommend that you upgrade your python-bleach packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-bleach", ver: "2.0-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-bleach-doc", ver: "2.0-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-bleach", ver: "2.0-1+deb9u1", rls: "DEB9" ) )){
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

