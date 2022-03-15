if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891726" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2016-9401", "CVE-2019-9924" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-11 22:29:00 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-03-25 23:00:00 +0100 (Mon, 25 Mar 2019)" );
	script_name( "Debian LTS: Security Advisory for bash (DLA-1726-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1726-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the DLA-1726-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two issues have been fixed in bash, the GNU Bourne-Again Shell:

CVE-2016-9401

The popd builtin segfaulted when called with negative out of range
offsets.

CVE-2019-9924

Sylvain Beucler discovered that it was possible to call commands
that contained a slash when in restricted mode (rbash) by adding
them to the BASH_CMDS array." );
	script_tag( name: "affected", value: "'bash' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.3-11+deb8u2.

We recommend that you upgrade your bash packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bash", ver: "4.3-11+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bash-builtins", ver: "4.3-11+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bash-doc", ver: "4.3-11+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bash-static", ver: "4.3-11+deb8u2", rls: "DEB8" ) )){
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

