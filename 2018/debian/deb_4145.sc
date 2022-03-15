if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704145" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2017-0915", "CVE-2017-0916", "CVE-2017-0917", "CVE-2017-0918", "CVE-2017-0925", "CVE-2017-0926", "CVE-2018-3710" );
	script_name( "Debian Security Advisory DSA 4145-1 (gitlab - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-18 00:00:00 +0100 (Sun, 18 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4145.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "gitlab on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 8.13.11+dfsg1-8+deb9u1.

We recommend that you upgrade your gitlab packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/gitlab" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Gitlab, a software
platform to collaborate on code:

CVE-2017-0915 / CVE-2018-3710
Arbitrary code execution in project import.

CVE-2017-0916
Command injection via Webhooks.

CVE-2017-0917
Cross-site scripting in CI job output.

CVE-2017-0918
Insufficient restriction of CI runner for project cache access.

CVE-2017-0925
Information disclosure in Services API.

CVE-2017-0926
Restrictions for disabled OAuth providers could be bypassed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gitlab", ver: "8.13.11+dfsg1-8+deb9u1", rls: "DEB9" ) )){
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

