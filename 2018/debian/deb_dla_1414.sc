if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891414" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-17458", "CVE-2017-9462", "CVE-2018-1000132" );
	script_name( "Debian LTS: Security Advisory for mercurial (DLA-1414-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 13:15:00 +0000 (Fri, 31 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "mercurial on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.1.2-2+deb8u5.

We recommend that you upgrade your mercurial packages." );
	script_tag( name: "summary", value: "Some security vulnerabilities were found in Mercurial which allow
authenticated users to trigger arbitrary code execution and
unauthorized data access in certain server configuration. Malformed
patches and repositories can also lead to crashes and arbitrary code
execution on clients.

CVE-2017-9462

In Mercurial before 4.1.3, 'hg serve --stdio' allows remote
authenticated users to launch the Python debugger, and
consequently execute arbitrary code, by using --debugger as a
repository name.

CVE-2017-17458

In Mercurial before 4.4.1, it is possible that a specially
malformed repository can cause Git subrepositories to run
arbitrary code in the form of a .git/hooks/post-update script
checked into the repository. Typical use of Mercurial prevents
construction of such repositories, but they can be created
programmatically.

CVE-2018-1000132

Mercurial version 4.5 and earlier contains a Incorrect Access
Control (CWE-285) vulnerability in Protocol server that can result
in Unauthorized data access. This attack appear to be exploitable
via network connectivity. This vulnerability appears to have been
fixed in 4.5.1.

OVE-20180430-0001

mpatch: be more careful about parsing binary patch data

OVE-20180430-0002

mpatch: protect against underflow in mpatch_apply

OVE-20180430-0004

mpatch: ensure fragment start isn't past the end of orig" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mercurial", ver: "3.1.2-2+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mercurial-common", ver: "3.1.2-2+deb8u5", rls: "DEB8" ) )){
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

