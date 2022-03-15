if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704246" );
	script_version( "2021-06-16T13:21:12+0000" );
	script_cve_id( "CVE-2018-0618" );
	script_name( "Debian Security Advisory DSA 4246-1 (mailman - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-15 00:00:00 +0200 (Sun, 15 Jul 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-06 20:15:00 +0000 (Wed, 06 May 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4246.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "mailman on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1:2.1.23-1+deb9u3.

We recommend that you upgrade your mailman packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/mailman" );
	script_tag( name: "summary", value: "Toshitsugu Yoneyama of Mitsui Bussan Secure Directions, Inc. discovered
that mailman, a web-based mailing list manager, is prone to a cross-site
scripting flaw allowing a malicious listowner to inject scripts into the
listinfo page, due to not validated input in the host_name field." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mailman", ver: "1:2.1.23-1+deb9u3", rls: "DEB9" ) )){
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

