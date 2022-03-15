if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892107" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-1930", "CVE-2020-1931" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-02 04:15:00 +0000 (Sun, 02 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-19 04:00:07 +0000 (Wed, 19 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for spamassassin (DLA-2107-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2107-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/950258" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spamassassin'
  package(s) announced via the DLA-2107-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in spamassassin, a Perl-based spam
filter using text analysis. Malicious rule or configuration files,
possibly downloaded from an updates server, could execute arbitrary
commands under multiple scenarios." );
	script_tag( name: "affected", value: "'spamassassin' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-0+deb8u3.

We recommend that you upgrade your spamassassin packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sa-compile", ver: "3.4.2-0+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamc", ver: "3.4.2-0+deb8u3", rls: "DEB8" ) )){
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
