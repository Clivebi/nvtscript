if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892131" );
	script_version( "2020-03-02T04:00:06+0000" );
	script_cve_id( "CVE-2013-2131", "CVE-2014-6262" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-03-02 04:00:06 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-02 04:00:06 +0000 (Mon, 02 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for rrdtool (DLA-2131-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2131-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rrdtool'
  package(s) announced via the DLA-2131-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple format string vulnerabilities in RRDtool, as used in Zenoss
Core before 4.2.5 and other products, allow remote attackers to
execute arbitrary code or cause a denial of service (application
crash) via a crafted third argument to the rrdtool.graph function, aka
ZEN-15415, a related issue to CVE-2013-2131." );
	script_tag( name: "affected", value: "'rrdtool' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.4.8-1.2+deb8u1.

We recommend that you upgrade your rrdtool packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblua5.1-rrd-dev", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblua5.1-rrd0", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrd-dev", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrd-ruby", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrd-ruby1.8", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrd-ruby1.9.1", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrd4", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrdp-perl", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librrds-perl", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-rrdtool", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rrdcached", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rrdtool", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rrdtool-dbg", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rrdtool-tcl", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-rrd", ver: "1.4.8-1.2+deb8u1", rls: "DEB8" ) )){
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

