if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704921" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-23017" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 05:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-29 03:00:04 +0000 (Sat, 29 May 2021)" );
	script_name( "Debian: Security Advisory for nginx (DSA-4921-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4921.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4921-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4921-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nginx'
  package(s) announced via the DSA-4921-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Luis Merino, Markus Vervier and Eric Sesterhenn discovered an off-by-one
in Nginx, a high-performance web and reverse proxy server, which could
result in denial of service and potentially the execution of arbitrary
code." );
	script_tag( name: "affected", value: "'nginx' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.14.2-2+deb10u4.

We recommend that you upgrade your nginx packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-auth-pam", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-cache-purge", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-dav-ext", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-echo", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-fancyindex", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-geoip", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-headers-more-filter", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-image-filter", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-lua", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-ndk", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-perl", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-subs-filter", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-uploadprogress", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-upstream-fair", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-xslt-filter", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-mail", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-nchan", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-rtmp", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-stream", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-common", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-doc", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-full", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-light", ver: "1.14.2-2+deb10u4", rls: "DEB10" ) )){
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

