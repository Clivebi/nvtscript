if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704198" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2017-18265" );
	script_name( "Debian Security Advisory DSA 4198-1 (prosody - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-09 00:00:00 +0200 (Wed, 09 May 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4198.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "prosody on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 0.9.12-2+deb9u1.

We recommend that you upgrade your prosody packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/prosody" );
	script_tag( name: "summary", value: "Albert Dengg discovered that incorrect parsing of messages
in the Prosody Jabber/XMPP server may result in denial of service.

The oldstable distribution (jessie) is not affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "prosody", ver: "0.9.12-2+deb9u1", rls: "DEB9" ) )){
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

