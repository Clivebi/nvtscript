if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892404" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2019-17637" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-10 02:15:00 +0000 (Sat, 10 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-10 03:00:09 +0000 (Sat, 10 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for eclipse-wtp (DLA-2404-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00016.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2404-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'eclipse-wtp'
  package(s) announced via the DLA-2404-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Eclipse Web Tools Platform, a component of the Eclipse IDE, XML and
DTD files referring to external entities could be exploited to send the
contents of local files to a remote server when edited or validated,
even when external entity resolution is disabled in the user
preferences." );
	script_tag( name: "affected", value: "'eclipse-wtp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
3.6.3-3+deb9u1.

We recommend that you upgrade your eclipse-wtp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "eclipse-wtp", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eclipse-wtp-servertools", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eclipse-wtp-webtools", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eclipse-wtp-ws", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eclipse-wtp-xmltools", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eclipse-wtp-xsl", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "w3c-xsd-xslt", ver: "3.6.3-3+deb9u1", rls: "DEB9" ) )){
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

