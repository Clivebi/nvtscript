if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891095" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839" );
	script_name( "Debian LTS: Security Advisory for freerdp (DLA-1095-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-25 15:20:00 +0000 (Fri, 25 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "freerdp on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0.1-1.1+deb7u4.

We recommend that you upgrade your freerdp packages." );
	script_tag( name: "summary", value: "Tyler Bohan of Talos discovered that FreeRDP, a free implementation of
the Remote Desktop Protocol (RDP), contained several vulnerabilities
that allowed a malicious remote server or a man-in-the-middle to
either cause a DoS by forcibly terminating the client, or execute
arbitrary code on the client side." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "freerdp-dbg", ver: "1.0.1-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "freerdp-x11", ver: "1.0.1-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-dev", ver: "1.0.1-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-plugins-standard", ver: "1.0.1-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp1", ver: "1.0.1-1.1+deb7u4", rls: "DEB7" ) )){
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

