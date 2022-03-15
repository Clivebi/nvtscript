if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704750" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-11724" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-29 16:33:00 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-08-27 03:00:11 +0000 (Thu, 27 Aug 2020)" );
	script_name( "Debian: Security Advisory for nginx (DSA-4750-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4750.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4750-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nginx'
  package(s) announced via the DSA-4750-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was reported that the Lua module for Nginx, a high-performance web
and reverse proxy server, is prone to a HTTP request smuggling
vulnerability." );
	script_tag( name: "affected", value: "'nginx' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.14.2-2+deb10u3.

We recommend that you upgrade your nginx packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-auth-pam", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-cache-purge", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-dav-ext", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-echo", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-fancyindex", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-geoip", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-headers-more-filter", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-image-filter", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-lua", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-ndk", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-perl", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-subs-filter", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-uploadprogress", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-upstream-fair", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-http-xslt-filter", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-mail", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-nchan", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-rtmp", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnginx-mod-stream", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-common", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-doc", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-full", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nginx-light", ver: "1.14.2-2+deb10u3", rls: "DEB10" ) )){
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
