if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892075" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2015-6748" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-27 00:15:00 +0000 (Mon, 27 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-27 04:00:04 +0000 (Mon, 27 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for jsoup (DLA-2075-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2075-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jsoup'
  package(s) announced via the DLA-2075-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in jsoup, a Java HTML parser that makes sense of
real-world HTML soup. Due to bad handling of missing '>' at EOF a
cross-site scripting (XSS) vulnerability could appear." );
	script_tag( name: "affected", value: "'jsoup' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.8.1-1+deb8u1.

We recommend that you upgrade your jsoup packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjsoup-java", ver: "1.8.1-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjsoup-java-doc", ver: "1.8.1-1+deb8u1", rls: "DEB8" ) )){
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

