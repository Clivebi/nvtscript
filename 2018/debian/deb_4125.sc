if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704125" );
	script_version( "2021-06-16T13:21:12+0000" );
	script_cve_id( "CVE-2018-6767", "CVE-2018-7253", "CVE-2018-7254" );
	script_name( "Debian Security Advisory DSA 4125-1 (wavpack - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 13:21:12 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-27 00:00:00 +0100 (Tue, 27 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-20 10:15:00 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4125.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "wavpack on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed
in version 5.0.0-2+deb9u1.

We recommend that you upgrade your wavpack packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/wavpack" );
	script_tag( name: "summary", value: "Joonun Jang discovered several problems in wavpack, an audio
compression format suite. Incorrect processing of input resulted in
several heap- and stack-based buffer overflows, leading to application
crash or potential code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libwavpack-dev", ver: "5.0.0-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwavpack1", ver: "5.0.0-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wavpack", ver: "5.0.0-2+deb9u1", rls: "DEB9" ) )){
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

