if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891578" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2016-1238", "CVE-2017-15705", "CVE-2018-11780", "CVE-2018-11781" );
	script_name( "Debian LTS: Security Advisory for spamassassin (DLA-1578-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-15 00:00:00 +0100 (Thu, 15 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 21:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00016.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "spamassassin on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.4.2-0+deb8u1. Upstream strongly advocates upgrading to the latest
upstream version so we are following that recommendation and
backported the version published as part of the 9.6 stretch release,
which also fixes many critical bugs.

We recommend that you upgrade your spamassassin packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were found in Spamassassin, which could lead
to Remote Code Execution and Denial of Service attacks under certain
circumstances.

CVE-2016-1238

Many Perl programs do not properly remove . (period) characters
from the end of the includes directory array, which might allow
local users to gain privileges via a Trojan horse module under the
current working directory.

CVE-2017-15705

A denial of service vulnerability was identified that exists in
Apache SpamAssassin before 3.4.2. The vulnerability arises with
certain unclosed tags in emails that cause markup to be handled
incorrectly leading to scan timeouts. This can cause carefully
crafted emails that might take more scan time than expected
leading to a Denial of Service.

CVE-2018-11780

A potential Remote Code Execution bug exists with the PDFInfo
plugin in Apache SpamAssassin before 3.4.2.

CVE-2018-11781

Apache SpamAssassin 3.4.2 fixes a local user code injection in the
meta rule syntax." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sa-compile", ver: "3.4.2-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamassassin", ver: "3.4.2-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spamc", ver: "3.4.2-0+deb8u1", rls: "DEB8" ) )){
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

