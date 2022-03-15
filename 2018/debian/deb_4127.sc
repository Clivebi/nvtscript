if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704127" );
	script_version( "2021-06-18T02:36:51+0000" );
	script_cve_id( "CVE-2017-12867", "CVE-2017-12869", "CVE-2017-12873", "CVE-2017-12874", "CVE-2017-18121", "CVE-2017-18122", "CVE-2018-6519", "CVE-2018-6521", "CVE-2018-7644" );
	script_name( "Debian Security Advisory DSA 4127-1 (simplesamlphp - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:36:51 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-02 00:00:00 +0100 (Fri, 02 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4127.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "simplesamlphp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1.13.1-2+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 1.14.11-1+deb9u1.

We recommend that you upgrade your simplesamlphp packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/simplesamlphp" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in SimpleSAMLphp, a
framework for authentication, primarily via the SAML protocol.

CVE-2017-12867
Attackers with access to a secret token could extend its validity
period by manipulating the prepended time offset.

CVE-2017-12869
When using the multiauth module, attackers can bypass authentication
context restrictions and use any authentication source defined in
the config.

CVE-2017-12873
Defensive measures have been taken to prevent the administrator
from misconfiguring persistent NameIDs to avoid identifier clash.
(Affects Debian 8 Jessie only.)

CVE-2017-12874
The InfoCard module could accept incorrectly signed XML messages
in rare occasions.

CVE-2017-18121
The consentAdmin module was vulnerable to a Cross-Site Scripting
attack, allowing an attacker to craft links that could execute
arbitrary JavaScript code in the victim's browser.

CVE-2017-18122
The (deprecated) SAML 1.1 implementation would regard as valid any
unsigned SAML response containing more than one signed assertion,
provided that the signature of at least one of the assertions was
valid, allowing an attacker that could obtain a valid signed
assertion from an IdP to impersonate users from that IdP.

CVE-2018-6519
Regular expression denial of service when parsing extraordinarily
long timestamps.

CVE-2018-6521
Change sqlauth module MySQL charset from utf8 to utf8mb to
prevent theoretical query truncation that could allow remote
attackers to bypass intended access restrictions

CVE-2018-7644
Critical signature validation vulnerability." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "simplesamlphp", ver: "1.13.1-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "simplesamlphp", ver: "1.14.11-1+deb9u1", rls: "DEB9" ) )){
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

