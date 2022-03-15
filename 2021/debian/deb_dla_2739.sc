if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892739" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-20314" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-19 17:02:00 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 09:50:29 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for libspf2 (DLA-2739-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2739-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2739-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libspf2'
  package(s) announced via the DLA-2739-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Philipp Jeitner and Haya Shulman discovered a stack-based buffer
overflow in libspf2, a library for validating mail senders with SPF,
which could result in denial of service, or potentially execution of
arbitrary code when processing a specially crafted SPF record." );
	script_tag( name: "affected", value: "'libspf2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.2.10-7+deb9u1.

We recommend that you upgrade your libspf2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmail-spf-xs-perl", ver: "1.2.10-7+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspf2-2", ver: "1.2.10-7+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspf2-2-dbg", ver: "1.2.10-7+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspf2-dev", ver: "1.2.10-7+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spfquery", ver: "1.2.10-7+deb9u1", rls: "DEB9" ) )){
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

