if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704214" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2018-8012" );
	script_name( "Debian Security Advisory DSA 4214-1 (zookeeper - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-06-01 00:00:00 +0200 (Fri, 01 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-14 12:13:00 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4214.html" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/ZOOKEEPER/Server-Server+mutual+authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "zookeeper on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 3.4.9-3+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 3.4.9-3+deb9u1.

We recommend that you upgrade your zookeeper packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/zookeeper" );
	script_tag( name: "summary", value: "It was discovered that Zookeeper, a service for maintaining configuration
information, enforced no authentication/authorisation when a server
attempts to join a Zookeeper quorum.

This update backports authentication support. Additional configuration
steps are needed, please see the references for additional information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java-doc", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt-dev", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt2", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st-dev", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st2", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper2", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-zookeeper", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper-bin", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeperd", ver: "3.4.9-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-java-doc", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt-dev", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-mt2", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st-dev", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper-st2", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzookeeper2", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-zookeeper", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeper-bin", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zookeeperd", ver: "3.4.9-3+deb9u1", rls: "DEB9" ) )){
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

