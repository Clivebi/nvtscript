if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704206" );
	script_version( "2021-06-18T02:36:51+0000" );
	script_cve_id( "CVE-2017-0920", "CVE-2018-8971" );
	script_name( "Debian Security Advisory DSA 4206-1 (gitlab - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:36:51 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-21 00:00:00 +0200 (Mon, 21 May 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-05 17:15:00 +0000 (Tue, 05 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4206.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "gitlab on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 8.13.11+dfsg1-8+deb9u2. The fix for CVE-2018-8971
also requires ruby-omniauth-auth0 to be upgraded
to version 2.0.0-0+deb9u1.

We recommend that you upgrade your gitlab packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/gitlab" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Gitlab, a software
platform to collaborate on code:

CVE-2017-0920
It was discovered that missing validation of merge requests allowed
users to see names to private projects, resulting in information
disclosure.

CVE-2018-8971
It was discovered that the Auth0 integration was implemented
incorrectly." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gitlab", ver: "8.13.11+dfsg1-8+deb9u2", rls: "DEB9" ) )){
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

