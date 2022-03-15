if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891495" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-1000116", "CVE-2017-1000117", "CVE-2017-12836", "CVE-2017-12976", "CVE-2017-9800", "CVE-2018-10857", "CVE-2018-10859" );
	script_name( "Debian LTS: Security Advisory for git-annex (DLA-1495-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-06 00:00:00 +0200 (Thu, 06 Sep 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "git-annex on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.20141125+oops-1+deb8u2.

We recommend that you upgrade your git-annex packages." );
	script_tag( name: "summary", value: "The git-annex package was found to have multiple vulnerabilities when
operating on untrusted data that could lead to arbitrary command
execution and encrypted data exfiltration.

CVE-2017-12976

git-annex before 6.20170818 allows remote attackers to execute
arbitrary commands via an ssh URL with an initial dash character
in the hostname, as demonstrated by an ssh://-eProxyCommand= URL,
a related issue to CVE-2017-9800, CVE-2017-12836,
CVE-2017-1000116, and CVE-2017-1000117.

CVE-2018-10857

git-annex is vulnerable to a private data exposure and
exfiltration attack. It could expose the content of files located
outside the git-annex repository, or content from a private web
server on localhost or the LAN.

CVE-2018-10859

git-annex is vulnerable to an Information Exposure when decrypting
files. A malicious server for a special remote could trick
git-annex into decrypting a file that was encrypted to the user's
gpg key. This attack could be used to expose encrypted data that
was never stored in git-annex" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "git-annex", ver: "5.20141125+oops-1+deb8u2", rls: "DEB8" ) )){
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

