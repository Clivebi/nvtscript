if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704194" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2018-1308" );
	script_name( "Debian Security Advisory DSA 4194-1 (lucene-solr - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-06 00:00:00 +0200 (Sun, 06 May 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-12 20:15:00 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4194.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "lucene-solr on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 3.6.2+dfsg-5+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 3.6.2+dfsg-10+deb9u2.

We recommend that you upgrade your lucene-solr packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/lucene-solr" );
	script_tag( name: "summary", value: "An XML external entity expansion vulnerability was discovered in the
DataImportHandler of Solr, a search server based on Lucene, which could
result in information disclosure." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-contrib-java", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java-doc", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolr-java", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-common", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-jetty", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-tomcat", ver: "3.6.2+dfsg-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-contrib-java", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java-doc", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolr-java", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-common", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-jetty", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-tomcat", ver: "3.6.2+dfsg-10+deb9u2", rls: "DEB9" ) )){
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

