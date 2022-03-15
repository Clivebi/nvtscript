if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891609" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2018-11759" );
	script_name( "Debian LTS: Security Advisory for libapache-mod-jk (DLA-1609-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-18 00:00:00 +0100 (Tue, 18 Dec 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:31:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/12/msg00007.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libapache-mod-jk on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.2.46-0+deb8u1.

We recommend that you upgrade your libapache-mod-jk packages." );
	script_tag( name: "summary", value: "A vulnerability has been discovered in libapache-mod-jk, the Apache 2
connector for the Tomcat Java servlet engine.

The libapache-mod-jk connector is susceptible to information disclosure
and privilege escalation because of a mishandling of URL normalization.

The nature of the fix required that libapache-mod-jk in Debian 8
'Jessie' be updated to the latest upstream release.  For reference, the
upstream changes associated with each release version are documented
in the linked references." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache-mod-jk-doc", ver: "1.2.46-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-jk", ver: "1.2.46-0+deb8u1", rls: "DEB8" ) )){
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

