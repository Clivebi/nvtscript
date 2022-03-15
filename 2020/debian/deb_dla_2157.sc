if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892157" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-8955", "CVE-2020-9759", "CVE-2020-9760" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-27 23:15:00 +0000 (Thu, 27 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-03-25 04:00:14 +0000 (Wed, 25 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for weechat (DLA-2157-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00031.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2157-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'weechat'
  package(s) announced via the DLA-2157-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in weechat, a fast, light and extensible
chat client.
All issues are about crafted messages, that could result in
a buffer overflow and application crash. This could cause a denial of
service or possibly have other impact." );
	script_tag( name: "affected", value: "'weechat' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.0.1-1+deb8u3.

We recommend that you upgrade your weechat packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "weechat", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "weechat-core", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "weechat-curses", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "weechat-dbg", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "weechat-dev", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "weechat-doc", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "weechat-plugins", ver: "1.0.1-1+deb8u3", rls: "DEB8" ) )){
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

