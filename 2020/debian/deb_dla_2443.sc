if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892443" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-15166" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-10 17:15:00 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 04:00:15 +0000 (Wed, 11 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for zeromq3 (DLA-2443-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00017.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2443-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zeromq3'
  package(s) announced via the DLA-2443-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that ZeroMQ, a lightweight messaging kernel
library does not properly handle connecting peers before a
handshake is completed. A remote, unauthenticated client connecting
to an application using the libzmq library, running with a socket
listening with CURVE encryption/authentication enabled can take
advantage of this flaw to cause a denial of service affecting
authenticated and encrypted clients." );
	script_tag( name: "affected", value: "'zeromq3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
4.2.1-4+deb9u3.

We recommend that you upgrade your zeromq3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzmq3-dev", ver: "4.2.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzmq5", ver: "4.2.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzmq5-dbg", ver: "4.2.1-4+deb9u3", rls: "DEB9" ) )){
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
