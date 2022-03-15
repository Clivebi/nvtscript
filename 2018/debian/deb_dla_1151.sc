if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891151" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-14990" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-1151-2)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/11/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u19.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "The fix for CVE-2017-14990 issued as DLA-1151-1 was incomplete and
caused a regression. It was discovered that an additional database
upgrade and further code changes would be necessary. At the moment
these changes are deemed as too intrusive and thus the initial patch
for CVE-2017-14990 has been removed again. For reference, the original
advisory text follows.

WordPress stores cleartext wp_signups.activation_key values (but
stores the analogous wp_users.user_activation_key values as hashes),
which might make it easier for remote attackers to hijack unactivated
user accounts by leveraging database read access (such as access
gained through an unspecified SQL injection vulnerability)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "3.6.1+dfsg-1~deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.6.1+dfsg-1~deb7u19", rls: "DEB7" ) )){
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

