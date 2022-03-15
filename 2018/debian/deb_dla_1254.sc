if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891254" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2017-12629" );
	script_name( "Debian LTS: Security Advisory for lucene-solr (DLA-1254-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-22 00:00:00 +0100 (Mon, 22 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 17:34:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00028.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "lucene-solr on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.6.0+dfsg-1+deb7u3.

We recommend that you upgrade your lucene-solr packages." );
	script_tag( name: "summary", value: "Michael Stepankin and Olga Barinova discovered a remote code execution
vulnerability in Apache Solr by exploiting XML External Entity
processing (XXE) in conjunction with use of a Config API add-listener
command to reach the RunExecutableListener class. To resolve this
issue the RunExecutableListener class has been removed and resolving
of external entities in the CoreParser class disallowed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-contrib-java", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java-doc", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolr-java", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-common", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-jetty", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-tomcat", ver: "3.6.0+dfsg-1+deb7u3", rls: "DEB7" ) )){
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

