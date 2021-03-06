if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703943" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2016-10376" );
	script_name( "Debian Security Advisory DSA 3943-1 (gajim - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-14 00:00:00 +0200 (Mon, 14 Aug 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-06 02:29:00 +0000 (Mon, 06 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3943.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gajim on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 0.16-1+deb8u2.

For the stable distribution (stretch), this problem has been fixed prior
to the initial release.

We recommend that you upgrade your gajim packages." );
	script_tag( name: "summary", value: "Gajim, a GTK+-based XMPP/Jabber client, unconditionally implements the
'XEP-0146: Remote Controlling Clients' extension, allowing a malicious
XMPP server to trigger commands to leak private conversations from
encrypted sessions. With this update XEP-0146 support has been disabled
by default and made opt-in via the remote_commands
option." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gajim", ver: "0.16-1+deb8u2", rls: "DEB8" ) ) != NULL){
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

