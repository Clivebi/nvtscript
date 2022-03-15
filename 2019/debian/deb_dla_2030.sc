if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892030" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2019-17267", "CVE-2019-17531" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 21:39:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-12-11 03:00:47 +0000 (Wed, 11 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for jackson-databind (DLA-2030-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2030-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the DLA-2030-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "More deserialization flaws were discovered in jackson-databind which
could allow an unauthenticated user to perform remote code execution.
The issue was resolved by extending the blacklist and blocking more
classes from polymorphic deserialization." );
	script_tag( name: "affected", value: "'jackson-databind' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.4.2-2+deb8u10.

We recommend that you upgrade your jackson-databind packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java", ver: "2.4.2-2+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java-doc", ver: "2.4.2-2+deb8u10", rls: "DEB8" ) )){
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

