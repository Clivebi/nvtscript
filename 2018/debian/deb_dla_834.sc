if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890834" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2016-6621" );
	script_name( "Debian LTS: Security Advisory for phpmyadmin (DLA-834-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-08 00:00:00 +0100 (Mon, 08 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/02/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "phpmyadmin on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4:3.4.11.1-2+deb7u8.

We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "summary", value: "A server-side request forgery vulnerability was reported for the setup
script in phpmyadmin, a MYSQL web administration tool. This flaw may
allow an unauthenticated attacker to brute-force MYSQL passwords,
detect internal hostnames or opened ports on the internal network.
Additionally there was a race condition between writing configuration
and administrator moving it allowing unauthenticated users to read or
alter it. Debian users who configured phpmyadmin via debconf and used
the default configuration for Apache 2 or Lighttpd were never affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:3.4.11.1-2+deb7u8", rls: "DEB7" ) )){
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

